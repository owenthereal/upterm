package internal

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// shortTempDir returns a directory a unix socket can actually be bound in.
// t.TempDir() on macOS hands out a /var/folders/<hash>/T/<TestName> path that
// is already past the 104-byte limit on sun_path before a filename is
// appended. Windows has no /tmp and its t.TempDir() is long for the same
// reason, so the temp root is used directly there.
func shortTempDir(t *testing.T) string {
	t.Helper()

	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	dir, err := os.MkdirTemp(base, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Test_AdminServer_ListenReportsABindFailure pins the half of the split that
// the host relies on: a socket that cannot be bound has to fail here, in the
// caller's own goroutine, rather than inside an actor where it would race the
// command's start and make the published reason a coin toss.
func Test_AdminServer_ListenReportsABindFailure(t *testing.T) {
	s := AdminServer{
		Session:    &api.GetSessionResponse{},
		ClientRepo: NewClientRepo(),
	}

	// A directory that does not exist, so the bind cannot succeed for a reason
	// that has nothing to do with timing.
	sock := filepath.Join(t.TempDir(), "no-such-directory", "admin.sock")
	require.Error(t, s.Listen(sock), "binding under a missing directory must fail")

	require.NoError(t, s.Shutdown(context.Background()),
		"a failed Listen leaves nothing to shut down")
}

// Test_AdminServer_ServeWithoutListenIsAnError keeps the other half honest:
// Serve must not quietly bind on the caller's behalf, because that is exactly
// the race the split removes.
func Test_AdminServer_ServeWithoutListenIsAnError(t *testing.T) {
	s := AdminServer{
		Session:    &api.GetSessionResponse{},
		ClientRepo: NewClientRepo(),
	}

	require.ErrorContains(t, s.Serve(context.Background()), "before Listen")
}

// Test_AdminServer_ListenSignalsBeforeServe is why the split is worth having:
// readiness is established by the bind, so it must be observable without any
// actor having run yet.
func Test_AdminServer_ListenSignalsBeforeServe(t *testing.T) {
	listening := make(chan struct{})
	s := AdminServer{
		Session:     &api.GetSessionResponse{},
		ClientRepo:  NewClientRepo(),
		OnListening: func() { close(listening) },
	}

	sock := filepath.Join(shortTempDir(t), "admin.sock")
	require.NoError(t, s.Listen(sock))
	select {
	case <-listening:
	default:
		t.Fatal("Listen returned without reporting that the socket is bound")
	}

	require.NoError(t, s.Shutdown(context.Background()))
}

// Test_AdminServer_StopSessionOnlyEndsTheLaunchItNames pins what a stop is
// bound to. The name and the socket path outlive the run that holds them --
// a session ends, gives the name back, and the next `upterm host` binds the
// same path -- so a client that read a record, then dialled, can reach a
// different session than the one it inspected. Only the launch ID
// distinguishes them, so it is what the request carries and what is checked
// before anything is stopped.
func Test_AdminServer_StopSessionOnlyEndsTheLaunchItNames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		held     string
		asked    string
		wantStop bool
		wantSays []string
	}{
		{
			name:     "the launch the caller read",
			held:     "launch-1",
			asked:    "launch-1",
			wantStop: true,
		},
		{
			// What a session that ended and was replaced between the record
			// read and this call looks like from here.
			name:     "another launch",
			held:     "launch-1",
			asked:    "launch-2",
			wantSays: []string{"launch-1", "launch-2"},
		},
		{
			// No caller that omits it exists -- the RPC is unreleased -- so
			// an empty value is a request that names no launch, not an old
			// client to be accommodated.
			name:     "no launch named",
			held:     "launch-1",
			asked:    "",
			wantSays: []string{"launch-1"},
		},
		{
			// A caller that supplied its own admin socket claimed no name,
			// so there is no launch a request could name.
			name:     "a session with no launch of its own",
			held:     "",
			asked:    "launch-1",
			wantSays: []string{"no launch", "launch-1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped := 0
			s := &adminServiceServer{
				Session:    &api.GetSessionResponse{},
				ClientRepo: NewClientRepo(),
				LaunchID:   tc.held,
				OnStop:     func() { stopped++ },
			}

			_, err := s.StopSession(context.Background(), &api.StopSessionRequest{LaunchId: tc.asked})

			if tc.wantStop {
				require.NoError(t, err)
				require.Equal(t, 1, stopped, "the launch the request named is the one that was stopped")
				return
			}
			require.Equal(t, codes.FailedPrecondition, status.Code(err),
				"a stop this session cannot answer for is a precondition failure, not a transport one")
			require.Zero(t, stopped, "nothing may be stopped for a request that does not name this launch")
			for _, says := range tc.wantSays {
				require.Contains(t, err.Error(), says,
					"the refusal has to name what was held and what was asked for")
			}
		})
	}
}

func TestGetSessionReportsEachClientsKind(t *testing.T) {
	repo := NewClientRepo()
	require.NoError(t, repo.Add(&api.Client{Id: "g", Kind: api.Client_GUEST}))
	require.NoError(t, repo.Add(&api.Client{Id: "h", Kind: api.Client_HOST}))

	s := &adminServiceServer{Session: &api.GetSessionResponse{}, ClientRepo: repo}
	resp, err := s.GetSession(context.Background(), &api.GetSessionRequest{})
	require.NoError(t, err)

	kinds := map[string]api.Client_Kind{}
	for _, c := range resp.ConnectedClients {
		kinds[c.Id] = c.Kind
	}
	require.Equal(t, map[string]api.Client_Kind{"g": api.Client_GUEST, "h": api.Client_HOST}, kinds)
}

// Match host.AdminClient's explicit Unix dialer: Windows socket paths cannot
// be used as gRPC URL targets. Keep the connection available for stream and
// transport-close assertions in the shutdown tests.
func adminTestConn(t *testing.T, socket string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
	require.NoError(t, err)
	return conn
}

// A header-only unary stream is accepted but cannot dispatch its handler until
// its body arrives. A later RPC on the same HTTP/2 transport is our acceptance
// barrier: the server has processed the earlier stream's headers first.
func TestAdminShutdownBoundsPendingRPC(t *testing.T) {
	s := &AdminServer{Session: &api.GetSessionResponse{}, ClientRepo: NewClientRepo()}
	sock := filepath.Join(shortTempDir(t), "admin.sock")
	require.NoError(t, s.Listen(sock))
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	conn := adminTestConn(t, sock)
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{}, "/api.AdminService/GetSession")
	require.NoError(t, err)
	_, err = api.NewAdminServiceClient(conn).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	shutdownCtx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(shutdownCtx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		// Release the held stream before reporting a regression.
		cancel()
		<-done
		t.Fatal("Shutdown ignored its context while a real RPC was pending")
	}
	require.Error(t, stream.RecvMsg(&api.GetSessionResponse{}), "forced shutdown closes the accepted stream")
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestAdminShutdownBeforeServe(t *testing.T) {
	s := &AdminServer{}
	require.NoError(t, s.Listen(filepath.Join(shortTempDir(t), "admin.sock")))
	require.NoError(t, s.Shutdown(context.Background()))
	require.Error(t, s.Serve(context.Background()))
	require.NoError(t, s.Shutdown(context.Background()))
}

// Transport closure does not release a callback that ignores cancellation.
// Exercise both a live RPC and a departed client: the latter lets gRPC's
// GracefulStop reach handlersWG.Wait while holding its internal mutex.
func TestAdminShutdownBoundsBlockedHandler(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		name := "connected"
		if closeClient {
			name = "client_closed"
		}
		t.Run(name, func(t *testing.T) {
			entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			s := &AdminServer{Session: &api.GetSessionResponse{}, ClientRepo: NewClientRepo(), LaunchID: "launch",
				OnStop: func() { close(entered); <-release; close(returned) },
			}
			sock := filepath.Join(shortTempDir(t), "admin.sock")
			require.NoError(t, s.Listen(sock))
			served := make(chan error, 1)
			go func() { served <- s.Serve(context.Background()) }()
			t.Cleanup(func() {
				close(release)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = s.Shutdown(ctx)
				select {
				case <-served:
				case <-time.After(time.Second):
					t.Error("Serve did not return after handler release")
				}
			})
			conn := adminTestConn(t, sock)
			defer func() { _ = conn.Close() }()
			rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer rpcCancel()
			rpcDone := make(chan error, 1)
			go func() {
				_, err := api.NewAdminServiceClient(conn).StopSession(rpcCtx, &api.StopSessionRequest{LaunchId: "launch"})
				rpcDone <- err
			}()
			select {
			case <-entered:
			case err := <-rpcDone:
				t.Fatalf("StopSession ended before entering its callback: %v", err)
			case <-rpcCtx.Done():
				t.Fatal("StopSession callback never entered")
			}
			if closeClient {
				require.NoError(t, conn.Close())
				select {
				case <-rpcDone:
				case <-rpcCtx.Done():
					t.Fatal("client close did not end RPC")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Shutdown(ctx) }()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Shutdown waited for a noncooperative StopSession callback beyond its deadline")
			}
			select {
			case <-returned:
				t.Fatal("callback was released before the bound was tested")
			default:
			}
			// Serve may still wait for gRPC's done signal, which requires the
			// callback to return. Cleanup releases it; Shutdown cannot kill it.
		})
	}
}

// SetJoinTimeout is bound to a launch for StopSession's reason: the name and
// the socket outlive the run, so only the launch ID says which session the
// caller inspected.
func Test_AdminServer_SetJoinTimeoutOnlyChangesTheLaunchItNames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		held     string
		asked    string
		wantSet  bool
		wantSays []string
	}{
		{name: "the launch the caller read", held: "launch-1", asked: "launch-1", wantSet: true},
		{name: "another launch", held: "launch-1", asked: "launch-2", wantSays: []string{"launch-1", "launch-2"}},
		{name: "no launch named", held: "launch-1", asked: "", wantSays: []string{"launch-1"}},
		{name: "a session with no launch of its own", held: "", asked: "launch-1", wantSays: []string{"no launch", "launch-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []time.Duration
			s := &adminServiceServer{
				Session:    &api.GetSessionResponse{},
				ClientRepo: NewClientRepo(),
				LaunchID:   tc.held,
				OnSetJoinTimeout: func(d time.Duration) *api.SetJoinTimeoutResponse {
					got = append(got, d)
					return &api.SetJoinTimeoutResponse{Outcome: api.SetJoinTimeoutResponse_COUNTING}
				},
			}

			resp, err := s.SetJoinTimeout(context.Background(), &api.SetJoinTimeoutRequest{LaunchId: tc.asked, TimeoutNanos: int64(time.Minute)})

			if tc.wantSet {
				require.NoError(t, err)
				require.Equal(t, api.SetJoinTimeoutResponse_COUNTING, resp.GetOutcome())
				require.Equal(t, []time.Duration{time.Minute}, got, "the duration reaches the session unchanged")
				return
			}
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Empty(t, got, "nothing may change for a request that does not name this launch")
			for _, says := range tc.wantSays {
				require.Contains(t, err.Error(), says)
			}
		})
	}
}

func Test_AdminServer_SetJoinTimeoutRefusesANegativeDuration(t *testing.T) {
	called := false
	s := &adminServiceServer{Session: &api.GetSessionResponse{}, ClientRepo: NewClientRepo(), LaunchID: "launch-1",
		OnSetJoinTimeout: func(time.Duration) *api.SetJoinTimeoutResponse { called = true; return nil }}
	_, err := s.SetJoinTimeout(context.Background(), &api.SetJoinTimeoutRequest{LaunchId: "launch-1", TimeoutNanos: -1})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.False(t, called)
}

func Test_AdminServer_SetJoinTimeoutWithoutAHandlerIsUnimplemented(t *testing.T) {
	s := &adminServiceServer{Session: &api.GetSessionResponse{}, ClientRepo: NewClientRepo(), LaunchID: "launch-1"}
	_, err := s.SetJoinTimeout(context.Background(), &api.SetJoinTimeoutRequest{LaunchId: "launch-1", TimeoutNanos: int64(time.Minute)})
	require.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestGetSessionReportsTheJoinStateAndLaunch(t *testing.T) {
	want := &api.JoinState{TimeoutNanos: int64(time.Minute), DeadlineUnixNano: 42}
	s := &adminServiceServer{Session: &api.GetSessionResponse{}, ClientRepo: NewClientRepo(), LaunchID: "launch-1",
		JoinState: func() *api.JoinState { return want }}
	resp, err := s.GetSession(context.Background(), &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Equal(t, want, resp.GetJoinState())
	require.Equal(t, "launch-1", resp.GetLaunchId(), "a reader validates the answer against the launch it read")

	s.JoinState = nil
	resp, err = s.GetSession(context.Background(), &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Nil(t, resp.GetJoinState(), "a server with no join state reports none")
}
