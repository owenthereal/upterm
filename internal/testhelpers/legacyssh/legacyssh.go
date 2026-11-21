// Package legacyssh runs a local, stock x/crypto v0.58 SSH peer for client
// interoperability tests. That peer counts every refused public-key offer
// against MaxAuthTries, including a limit of one. Its explicit testdata modfile
// keeps the historical library out of upterm's dependency graph and binaries.
package legacyssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Config describes one connection. The peer accepts pty and shell requests,
// answers keepalives, and sends Exit if set. Allow is a marshalled public key;
// nil accepts any key unless RefuseAll is set.
type Config struct {
	MaxAuthTries int
	RefuseAll    bool
	Allow        []byte
	Version      string
	Banner       string
	Exit         *int
}

// Peer owns a host key shared by its connections. New must run before the
// test starts its handshake or join deadline: it builds the helper once per
// test binary. Serve starts only the already-built executable.
type Peer struct {
	HostKey ssh.Signer
	t       testing.TB
	binary  string
	private []byte
	events  string
}

var buildDir string

var build = sync.OnceValues(func() (string, error) {
	var err error
	buildDir, err = os.MkdirTemp("", "upterm-legacy-ssh-")
	if err != nil {
		return "", err
	}
	binary := filepath.Join(buildDir, "peer")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	// Both callers, host and join, run one directory below the module root.
	// Use their working directory so source discovery also works with -trimpath.
	peerDir, err := filepath.Abs(filepath.Join("..", "internal", "testhelpers", "legacyssh", "testdata", "peer"))
	if err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-mod=readonly", "-modfile="+filepath.Join(peerDir, "legacy.mod"), "-o", binary, ".")
	cmd.Dir = peerDir
	// Build for the running test, independently of workspace/modfile flags or
	// a cross-compilation target inherited from its caller.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0",
		"GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build historical SSH peer: %w\n%s", err, out)
	}
	return binary, nil
})

// Suite cleans up the lazily built peer after the tests, before TestMain's
// goroutine-leak check. Embedding M preserves the usual TestMain lifecycle.
type Suite struct{ *testing.M }

func (s Suite) Run() int {
	defer func() { _ = os.RemoveAll(buildDir) }()
	return s.M.Run()
}

func New(t testing.TB) *Peer {
	t.Helper()
	binary, err := build()
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return &Peer{HostKey: signer, t: t, binary: binary, private: pem.EncodeToMemory(block), events: t.TempDir()}
}

// Serve carries an ordinary SSH connection to the historical peer over its
// standard pipes. The peer records its authentication callbacks in a local
// file before replying. Reading those records before forwarding its SSH output
// preserves the fixture's observations without changing the SSH wire stream.
// Observe receives offer/authenticated keys, and may be nil.
func (p *Peer) Serve(conn net.Conn, config Config, observe func(kind string, data []byte)) {
	defer func() { _ = conn.Close() }()
	events, err := os.CreateTemp(p.events, "connection-")
	if err != nil {
		p.t.Errorf("historical SSH peer observations: %v", err)
		return
	}
	defer func() { _ = events.Close() }()
	cmd := exec.CommandContext(p.t.Context(), p.binary)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		p.t.Errorf("historical SSH peer stdin: %v", err)
		return
	}
	defer func() { _ = in.Close() }()
	out, err := cmd.StdoutPipe()
	if err != nil {
		p.t.Errorf("historical SSH peer stdout: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		p.t.Errorf("start historical SSH peer: %v", err)
		return
	}
	if err := json.NewEncoder(in).Encode(struct {
		Config
		HostKey []byte
		Events  string
	}{config, p.private, events.Name()}); err != nil {
		p.t.Errorf("configure historical SSH peer: %v", err)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return
	}
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(in, conn)
		_ = in.Close()
	}()
	writer := &observedWriter{Writer: conn, events: events, observe: observe}
	_, copyErr := io.Copy(writer, out)
	if writer.err != nil && p.t.Context().Err() == nil {
		p.t.Errorf("historical SSH peer observations: %v", writer.err)
	}
	_ = conn.Close()
	_ = in.Close()
	<-inputDone
	// A client that left during a write can leave the peer blocked on stdout.
	if copyErr != nil {
		_ = cmd.Process.Kill()
	}
	if err := cmd.Wait(); err != nil && copyErr == nil && p.t.Context().Err() == nil {
		p.t.Errorf("historical SSH peer: %v\n%s", err, &stderr)
	}
}

type observedWriter struct {
	io.Writer
	events  *os.File
	observe func(string, []byte)
	err     error
}

func (w *observedWriter) Write(data []byte) (int, error) {
	// Only the peer's serial authentication callbacks append records, before
	// their SSH replies. Its ordinary client waits for each reply before the
	// next offer, so all records available here are complete.
	decoder := json.NewDecoder(w.events)
	for {
		var event struct {
			Kind string
			Data []byte
		}
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			w.err = err
			return 0, err
		}
		if w.observe != nil {
			w.observe(event.Kind, event.Data)
		}
	}
	return w.Writer.Write(data)
}
