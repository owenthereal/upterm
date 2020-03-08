package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	chshare "github.com/jpillora/chisel/share"

	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/host/api"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 8192

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

func WrapWSConn(ws *websocket.Conn) net.Conn {
	return chshare.NewWebSocketConn(ws)
}

type WebsocketServer struct {
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger

	srv *http.Server
	mux sync.Mutex
}

func (s *WebsocketServer) Serve(ln net.Listener) error {
	s.mux.Lock()
	h := &wsHandler{
		sshdDialListener:    s.SSHDDialListener,
		sessionDialListener: s.SessionDialListener,
		logger:              s.Logger,
	}
	s.srv = &http.Server{
		Handler: h,
	}
	s.mux.Unlock()

	return s.srv.Serve(ln)
}

func (s *WebsocketServer) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.srv.Shutdown(context.Background())
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type wsHandler struct {
	sshdDialListener    SSHDDialListener
	sessionDialListener SessionDialListener
	logger              log.FieldLogger
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

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		httpError(w, fmt.Errorf("ws upgrade failed"))
		return
	}
	defer ws.Close()

	id, err := api.DecodeIdentifier(user+":"+pass, string(clientVersion))
	if err != nil {
		wsError(ws, err, "error decoding id")
		return
	}

	var conn net.Conn
	// TODO: dial different host
	if id.Type == api.Identifier_HOST {
		conn, err = h.sshdDialListener.Dial()
	} else {
		conn, err = h.sessionDialListener.Dial(id.Id)
	}
	if err != nil {
		wsError(ws, err, "error dialing")
		return
	}

	wsconn := WrapWSConn(ws)

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

	if err := g.Run(); err != nil {
		wsError(ws, err, "error piping")
	}
}

func httpError(w http.ResponseWriter, err error) {
	log.WithError(err).Error("http error")
	w.WriteHeader(400)
	w.Write([]byte(err.Error()))
}

func wsError(ws *websocket.Conn, err error, msg string) {
	log.WithError(err).Error(msg)
	ws.WriteMessage(websocket.TextMessage, []byte(err.Error()))
}
