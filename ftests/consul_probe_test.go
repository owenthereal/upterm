package ftests

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/testhelpers"
)

func TestConsulAvailabilityClosesItsIdleConnection(t *testing.T) {
	closed := make(chan struct{})
	var once sync.Once
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`"127.0.0.1:8300"`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			once.Do(func() { close(closed) })
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	t.Setenv("CONSUL_URL", server.URL)

	if !testhelpers.IsConsulAvailable() {
		t.Fatal("the healthy Consul probe failed")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("the completed Consul probe left its owned HTTP connection open")
	}
}

func TestConsulAvailabilityCancelsItsTimedOutRequest(t *testing.T) {
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	t.Setenv("CONSUL_URL", server.URL)

	if testhelpers.IsConsulAvailable() {
		t.Fatal("a stalled Consul probe reported success")
	}
	select {
	case <-started:
	default:
		t.Fatal("the probe never reached the controlled HTTP handler")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("the timed-out Consul request survived the helper's return")
	}
}
