package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/ws"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
)

type WebSocketProxy struct {
	ConnDialer connDialer

	srv *http.Server
	mux sync.Mutex
}

func (s *WebSocketProxy) Serve(ln net.Listener) error {
	s.mux.Lock()
	s.srv = &http.Server{
		Handler: &wsHandler{
			ConnDialer: s.ConnDialer,
		},
	}
	s.mux.Unlock()

	return s.srv.Serve(ln)
}

func (s *WebSocketProxy) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.srv != nil {
		return s.srv.Shutdown(context.Background())
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
}

// ssh://user:pass@uptermd.upterm.dev (port 22)
// ws(s)://uptermd.upterm.dev (port 80 or 443)
// Authorization: Basic user:pass
// Upterm-Client-Version: SSH-2.0-upterm-host-client
func (h *wsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientVersion := r.Header.Get("Upterm-Client-Version")
	if clientVersion == "" {
		httpError(w, fmt.Errorf("missing upterm client version"))
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		httpError(w, fmt.Errorf("basic auth failed"))
		return
	}

	wsc, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		httpError(w, fmt.Errorf("ws upgrade failed"))
		return
	}
	wsconn := ws.WrapWSConn(wsc)
	defer wsconn.Close()

	id, err := api.DecodeIdentifier(user+":"+pass, string(clientVersion))
	if err != nil {
		wsError(wsconn, err, "error decoding id")
		return
	}

	conn, err := h.ConnDialer.Dial(*id)
	if err != nil {
		wsError(wsconn, err, "error dialing")
		return
	}

	var o sync.Once
	close := func() {
		wsconn.Close()
		conn.Close()
	}

	var g run.Group
	{
		g.Add(func() error {
			_, err := io.Copy(wsconn, conn)
			return err
		}, func(err error) {
			o.Do(close)
		})
	}
	{
		g.Add(func() error {
			_, err := io.Copy(conn, wsconn)
			return err
		}, func(err error) {
			o.Do(close)
		})
	}

	if err := g.Run(); err != nil && !isWSIgnoredError(err) {
		wsError(wsconn, err, "error piping")
	}
}

func isWSIgnoredError(err error) bool {
	return strings.Contains(err.Error(), "unexpected EOF")
}

func httpError(w http.ResponseWriter, err error) {
	log.WithError(err).Error("http error")
	w.WriteHeader(400)
	_, _ = w.Write([]byte(err.Error()))
}

func wsError(conn net.Conn, err error, msg string) {
	log.WithError(err).Error(msg)
	_, _ = conn.Write([]byte(err.Error()))
}
