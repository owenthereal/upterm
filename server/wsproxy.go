package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/ws"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
)

type webSocketProxy struct {
	ConnDialer connDialer
	Logger     log.FieldLogger

	srv *http.Server
	mux sync.Mutex
}

func webHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/getting-started") {
			h.ServeHTTP(w, r)
			return
		}

		w.Header().Add("Content-Type", "text/plain")
		// TODO: better getting-started guide
		data := `1. Install the upterm CLI by following https://github.com/jingweno/upterm#installation.
2. On your machine, host a session with "upterm host --server wss://%s -- YOUR_COMMAND". More details in https://github.com/jingweno/upterm#quick-start.
3. Your pair(s) join the session with "ssh -o ProxyCommand='upterm proxy wss://TOKEN@%s' TOKEN@%s:443".
`
		fmt.Fprint(w, fmt.Sprintf(data, r.Host, r.Host, r.Host))
	})
}

func (s *webSocketProxy) Serve(ln net.Listener) error {
	s.mux.Lock()
	s.srv = &http.Server{
		Handler: webHandler(&wsHandler{
			ConnDialer: s.ConnDialer,
			Logger:     s.Logger,
		}),
	}
	s.mux.Unlock()

	return s.srv.Serve(ln)
}

func (s *webSocketProxy) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.srv != nil {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(serverShutDownDeadline))
		defer cancel()

		return s.srv.Shutdown(ctx)
	}

	return nil
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type wsHandler struct {
	ConnDialer connDialer
	Logger     log.FieldLogger
}

// ServeHTTP checks the following header:
// * Authorization
// * Upterm-Client-Version
func (h *wsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientVersion := r.Header.Get("Upterm-Client-Version")
	if clientVersion == "" {
		h.httpError(w, fmt.Errorf("missing upterm client version"))
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		h.httpError(w, fmt.Errorf("basic auth failed"))
		return
	}

	wsc, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.httpError(w, fmt.Errorf("ws upgrade failed"))
		return
	}
	wsconn := ws.WrapWSConn(wsc)
	defer wsconn.Close()

	id, err := api.DecodeIdentifier(user+":"+pass, string(clientVersion))
	if err != nil {
		h.wsError(wsc, err, "error decoding id")
		return
	}

	conn, err := h.ConnDialer.Dial(*id)
	if err != nil {
		h.wsError(wsc, err, "error dialing")
		return
	}

	var o sync.Once
	cl := func() {
		wsconn.Close()
		conn.Close()
	}

	var g run.Group
	{
		g.Add(func() error {
			_, err := io.Copy(wsconn, conn)
			return err
		}, func(err error) {
			o.Do(cl)
		})
	}
	{
		g.Add(func() error {
			_, err := io.Copy(conn, wsconn)
			return err
		}, func(err error) {
			o.Do(cl)
		})
	}

	if err := g.Run(); err != nil && !isWSIgnoredError(err) {
		h.wsError(wsc, err, "error piping")
	}
}

func (h *wsHandler) httpError(w http.ResponseWriter, err error) {
	h.Logger.WithError(err).Error("http error")
	w.WriteHeader(400)
	_, _ = w.Write([]byte(err.Error()))
}

func (h *wsHandler) wsError(ws *websocket.Conn, err error, msg string) {
	h.Logger.WithError(err).Error(msg)
	_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()))
}

func isWSIgnoredError(err error) bool {
	return strings.Contains(err.Error(), "unexpected EOF")
}
