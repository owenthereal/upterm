package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

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

type WebsocketServer struct {
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener

	srv *http.Server
	mux sync.Mutex
}

func (s *WebsocketServer) Serve(ln net.Listener) error {
	s.mux.Lock()
	h := &wsHandler{
		sshdDialListener:    s.SSHDDialListener,
		sessionDialListener: s.SessionDialListener,
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

var upgrader = websocket.Upgrader{}

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
		wsError(ws, err)
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
		wsError(ws, err)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	closeFunc := func(ws *websocket.Conn) {
		if err := ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeWait),
		); err != nil {
			log.WithError(err).Error("error closing ws")
		}
	}
	defer closeFunc(ws)

	var g run.Group
	{
		g.Add(func() error {
			return pumpReader(ws, conn, ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return ping(ws, ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return pumpWriter(ws, conn, ctx)
		}, func(err error) {
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		wsError(ws, err)
	}
}

func pumpWriter(ws *websocket.Conn, w io.Writer, ctx context.Context) error {
	ws.SetReadLimit(maxMessageSize)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// ignore
		}

		_, message, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if _, err := w.Write(message); err != nil {
			return err
		}
	}
}

func pumpReader(ws *websocket.Conn, r io.Reader, ctx context.Context) error {
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanBytes) // this may generate tons of requests
	for s.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// ignore
		}

		ws.SetWriteDeadline(time.Now().Add(writeWait))
		if err := ws.WriteMessage(websocket.TextMessage, s.Bytes()); err != nil {
			return err
		}
	}

	return s.Err()
}

func ping(ws *websocket.Conn, ctx context.Context) error {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func httpError(w http.ResponseWriter, err error) {
	log.WithError(err).Error("http error")
	w.WriteHeader(400)
	w.Write([]byte(err.Error()))
}

func wsError(ws *websocket.Conn, err error) {
	log.WithError(err).Error("ws error")
	ws.WriteMessage(websocket.TextMessage, []byte(err.Error()))
}
