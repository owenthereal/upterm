package main

// Run with go test -modfile=legacy.mod from this directory.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type failingWriter struct {
	writesBeforeFailure int
	err                 error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.writesBeforeFailure == 0 {
		return 0, w.err
	}
	w.writesBeforeFailure--
	return len(p), nil
}

func TestObservationFailureIsNotAnAuthenticationRefusal(t *testing.T) {
	broken := errors.New("observation writer failed before writing any bytes")
	for _, tc := range []struct {
		name      string
		writer    io.Writer
		refuseAll bool
		want      error
	}{
		{"offered key", &failingWriter{err: broken}, false, broken},
		{"verified key", &failingWriter{writesBeforeFailure: 1, err: broken}, false, broken},
		{"ordinary refusal", new(bytes.Buffer), true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			block, err := ssh.MarshalPrivateKey(private, "")
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			client, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			server, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- serve(server, config{MaxAuthTries: 1, RefuseAll: tc.refuseAll,
					HostKey: pem.EncodeToMemory(block)}, tc.writer)
			}()
			conn, _, _, err := ssh.NewClientConn(client, ln.Addr().String(), &ssh.ClientConfig{
				User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			})
			if err == nil {
				_ = conn.Close()
				t.Fatal("the peer unexpectedly authenticated the client")
			}
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("peer returned %v, want %v", err, tc.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the peer did not finish after the handshake failed")
			}
		})
	}
}
