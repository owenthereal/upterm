package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/test/bufconn"
)

type testSshdDialListener struct {
	*bufconn.Listener
}

func (l *testSshdDialListener) Dial() (net.Conn, error) {
	return l.Listener.Dial()
}

func (l *testSshdDialListener) Listen() (net.Listener, error) {
	return l.Listener, nil
}

type testSessionDialListener struct {
	*bufconn.Listener
}

func (l *testSessionDialListener) Dial(id string) (net.Conn, error) {
	return l.Listener.Dial()
}

func (l *testSessionDialListener) Listen(id string) (net.Listener, error) {
	return l.Listener, nil
}

func Test_WebSocketProxy_Host(t *testing.T) {
	cd := connDialer{
		SSHDDialListener:    &testSshdDialListener{bufconn.Listen(1024)},
		SessionDialListener: &testSessionDialListener{bufconn.Listen(1024)},
		Logger:              log.New(),
	}
	wsh := &wsHandler{
		ConnDialer: cd,
	}
	ts := httptest.NewServer(wsh)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"

	header := utils.WebSocketDialHeader("owen", "", false)
	wsc, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		t.Fatal(err)
	}

	rr, rw := io.Pipe()
	rs := bufio.NewScanner(rr)
	go func(conn *websocket.Conn, w io.Writer) {
		for {
			wt, b, err := conn.ReadMessage()
			if err != nil {
				fmt.Println(err)
			}

			if wt != websocket.BinaryMessage {
				continue
			}

			_, _ = rw.Write(b)
		}
	}(wsc, rw)

	ln, err := cd.SSHDDialListener.Listen()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	wr, ww := io.Pipe()
	ws := bufio.NewScanner(wr)
	go func() {
		_, _ = io.Copy(ww, conn)
	}()

	// test read
	_, _ = conn.Write([]byte("read\n")) // need CR because func scan scans by line
	if diff := cmp.Diff("read", scan(rs)); diff != "" {
		t.Fatal(diff)
	}

	// test write
	if err := wsc.WriteMessage(websocket.BinaryMessage, []byte("write\n")); err != nil { // need CR because func scan scans by line
		t.Fatal(err)
	}
	if diff := cmp.Diff("write", scan(ws)); diff != "" {
		t.Fatal(diff)
	}
}

func scan(s *bufio.Scanner) string {
	for s.Scan() {
		return s.Text()
	}

	return s.Err().Error()
}
