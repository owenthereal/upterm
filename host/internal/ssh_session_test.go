package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRawSessionOutput(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		Handler: func(sess gssh.Session) {
			_, _ = io.Copy(sess, sess)
		},
		ChannelHandlers: map[string]gssh.ChannelHandler{"session": rawSessionHandler},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		<-done
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{
		User: "guest", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	var inputs []io.WriteCloser
	var outputs []io.Reader
	// Keep both sessions open on one connection. A raw channel stored on the
	// connection context would send the first session's output to the second.
	for range 2 {
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer sess.Close()
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		input, err := sess.StdinPipe()
		require.NoError(t, err)
		output, err := sess.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Shell())
		inputs = append(inputs, input)
		outputs = append(outputs, output)
	}

	// Reading each write before sending the next forces CR and LF to cross
	// separate SSH writes, where stateless newline normalization also corrupts
	// an otherwise ordinary CRLF. No native PTY is needed, so this covers Windows.
	for _, chunk := range []string{"HELLO   ", "\n", "HELLO", "\r", "\n", "\r\r\n", "\x1b[12;9Hpane\nnext", "\x00\t☃"} {
		for i := range inputs {
			_, err := io.WriteString(inputs[i], chunk)
			require.NoError(t, err)
			got := make([]byte, len(chunk))
			_, err = io.ReadFull(outputs[i], got)
			require.NoError(t, err)
			require.Equal(t, chunk, string(got))
		}
	}
}
