package capacity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/termsize"
	"golang.org/x/crypto/ssh"
)

const finalDrainLimit = 10 * time.Second
const retryQueueLimit = 5 * time.Second

type runState struct {
	hostReadyTimeout  time.Duration
	guestReadyTimeout time.Duration
	canary            *guest
	guestIdentity     ssh.Signer
	clientsMu         sync.RWMutex
	telemetryMu       sync.Mutex
	lastTelemetry     map[string]time.Time
	cfg               Config
	guard             *guard
	rec               *recorder
	ctx               context.Context
	cancel            context.CancelCauseFunc
	hosts             []*hostRun
	guests            []*guest
	proxies           []*tunnelProxy
	workers           sync.WaitGroup
	activeWorkers     sync.WaitGroup
	helper            string
	dir               string
}
type tunnelObservation struct {
	event host.TunnelEvent
	at    time.Time
}
type hostRun struct {
	repair      sync.Mutex
	id          int
	socket      string
	proxy       *tunnelProxy
	h           *host.Host
	done        chan error
	mu          sync.Mutex
	initial     *api.GetSessionResponse
	established bool
	expectedCut bool
	tunnel      chan tunnelObservation
	started     bool
}

func (r *runState) hostTunnel(h *hostRun, e host.TunnelEvent) {
	h.mu.Lock()
	unexpected := !e.Up && h.established && !h.expectedCut
	if e.Up {
		// Up means the host's guest door is live again. A later loss is a
		// separate outage, even while planned guest repairs are still running.
		h.expectedCut = false
	}
	h.mu.Unlock()
	if unexpected && r.ctx.Err() == nil {
		r.fail(fmt.Errorf("unexpected host transport loss: host=%d", h.id))
	}
	if e.Up {
		h.proxy.ready()
	}
	r.rec.event("host_tunnel", map[string]any{"host": h.id, "up": e.Up, "can_reconnect": e.CanReconnect, "route_changed": e.RouteChanged})
	select {
	case h.tunnel <- tunnelObservation{event: e, at: time.Now()}:
	default:
		r.fail(errors.New("host tunnel event overflow"))
	}
}

func (h *hostRun) session(ctx context.Context) (*api.GetSessionResponse, error) {
	conn, err := host.AdminConn(h.socket)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	s, err := api.NewAdminServiceClient(conn).GetSession(ctx, &api.GetSessionRequest{})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	initial := h.initial
	h.mu.Unlock()
	if initial == nil || s.SessionId != initial.SessionId {
		return nil, errors.New("host session identity changed")
	}
	return s, nil
}
func (r *runState) fail(err error) { r.cancel(err) }
func (r *runState) reserve(n int64) error {
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	if n > r.cfg.PayloadBudgetBytes-r.rec.summary.ReservedPayloadBytes {
		return errors.New("payload_budget")
	}
	r.rec.summary.ReservedPayloadBytes += n
	return nil
}
func (r *runState) actual(n int64) {
	r.rec.mu.Lock()
	r.rec.summary.PayloadBytes += n
	r.rec.mu.Unlock()
}
func (r *runState) send(q *guest, w io.Writer, stream, seq int) error {
	return r.sendKind(q, w, stream, seq, "I")
}
func (r *runState) sendKind(q *guest, w io.Writer, stream, seq int, kind string) error {
	fanout := r.cfg.GuestsPerHost * r.cfg.ChannelsPerGuest
	if q.canary {
		fanout = 1
	}
	if err := r.reserve(128 * int64(1+fanout)); err != nil {
		return err
	}
	now := time.Now()
	key := fmt.Sprintf("%d:%d", stream, seq)
	switch kind {
	case "I":
		q.mu.Lock()
		if q.pending == nil {
			q.pending = map[string]time.Time{}
		}
		q.pending[key] = now
		q.mu.Unlock()
	case "R":
		q.mu.Lock()
		if q.challenges == nil {
			q.challenges = map[string]time.Time{}
		}
		q.challenges[fmt.Sprintf("%d:%d:%d", stream, seq, now.UnixNano())] = now
		q.mu.Unlock()
	}
	n, err := w.Write(frame(kind, stream, seq, now, 128))
	if n == 128 {
		r.rec.mu.Lock()
		if kind == "I" {
			r.rec.summary.InputFrames++
		} else {
			r.rec.summary.HandshakeFrames++
		}
		r.rec.mu.Unlock()
	}
	r.actual(int64(n))
	if n != 128 && err == nil {
		err = io.ErrShortWrite
	}
	if kind == "I" && n != 128 {
		q.mu.Lock()
		delete(q.pending, key)
		q.mu.Unlock()
	}
	return err
}
func (r *runState) startHost(index int, t Target, identity ssh.Signer) error {
	u, err := transport(t, r.cfg.HostWSPercent, index, r.cfg.Hosts, r.cfg.HostPublic)
	if err != nil {
		return err
	}
	proxy, err := newTunnelProxy(r.ctx, r.guard, t)
	if err != nil {
		return err
	}
	r.clientsMu.Lock()
	r.proxies = append(r.proxies, proxy)
	r.clientsMu.Unlock()
	dir := filepath.Join(r.dir, "h"+strconv.Itoa(index))
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	ready := make(chan string, 1)
	h := &hostRun{id: index, socket: filepath.Join(dir, "admin.sock"), proxy: proxy, done: make(chan error, 1), tunnel: make(chan tunnelObservation, 16)}
	if identity == nil {
		identity, err = makeSigner()
		if err != nil {
			return err
		}
	}
	key, err := makeSigner()
	if err != nil {
		return err
	}
	timeout := r.hostReadyTimeout
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	proxy.serviceTimeout = timeout
	proxy.failure = r.fail
	proxy.queueEvent = func(wait time.Duration, limited bool) {
		r.rec.event("admission_queue", map[string]any{"role": "host", "host": index, "retry": true, "queue_ms": float64(wait) / float64(time.Millisecond), "generator_limited": limited})
	}
	commandDir := dir
	var root *os.Root
	var writeLimits *host.SFTPWriteLimits
	if r.cfg.TransferConcurrency > 0 {
		writeLimits = &host.SFTPWriteLimits{Files: make(map[string]int64)}
		for transfer := 0; transfer < r.cfg.TransferConcurrency; transfer++ {
			guest := transfer % (r.cfg.Hosts * r.cfg.GuestsPerHost)
			if guest/r.cfg.GuestsPerHost == index {
				writeLimits.Files[fmt.Sprintf("transfer-%d.bin", transfer)] = TransferSize
				writeLimits.TotalBytes += TransferSize
			}
		}
		commandDir = filepath.Join(dir, "transfers")
		if err := os.Mkdir(commandDir, 0700); err != nil {
			return err
		}
		root, err = os.OpenRoot(commandDir)
		if err != nil {
			return err
		}
	}
	h.h = &host.Host{Reconnect: host.ReconnectTiming{AttemptDeadline: 30*time.Second + retryQueueLimit}, KeepAliveDuration: 50 * time.Second, Host: u.String(), Command: []string{r.helper, "helper", strconv.Itoa(index), strconv.FormatBool(r.cfg.Active)}, CommandDir: commandDir, Signers: []ssh.Signer{identity}, IdentitiesOnly: true, HostKey: key, HostKeyCallback: pinnedKey(t), ProxyURL: proxy.url, AdminSocketFile: h.socket, AutoAccept: true, SFTPAutoAccept: true, SFTPDisabled: root == nil, SFTPRoot: root, ForwardingDisabled: true, ExecDisabled: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), StopGrace: time.Second, PtySize: termsize.Size{Cols: 2048, Rows: 100}, PinPtySize: true,
		SFTPWriteLimits: writeLimits,
		AuthorizedKeys:  []*host.AuthorizedKey{{PublicKeys: []ssh.PublicKey{r.guestIdentity.PublicKey()}}},
		SessionCreatedCallback: func(ctx context.Context, s *api.GetSessionResponse) error {
			if err := r.guard.session(ctx, s); err != nil {
				return err
			}
			h.mu.Lock()
			h.initial = s
			h.mu.Unlock()
			return nil
		},
		SessionReadyCallback: func(status string) {
			h.mu.Lock()
			h.established = status == "ready"
			h.mu.Unlock()
			proxy.ready()
			select {
			case ready <- status:
			default:
			}
		},
		TunnelCallback: func(e host.TunnelEvent) {
			r.hostTunnel(h, e)
		},
	}
	r.hosts[index] = h
	queuedAt := time.Now()
	permit, err := r.guard.permit(r.ctx)
	if err != nil {
		h.done <- err
		return err
	}
	proxy.mu.Lock()
	proxy.permit = permit
	proxy.mu.Unlock()
	r.rec.event("admission_queue", map[string]any{"role": "host", "host": index, "queue_ms": float64(time.Since(queuedAt)) / float64(time.Millisecond)})
	var began time.Time
	h.started = true
	go func() {
		err := h.h.Run(r.ctx)
		h.done <- err
		if r.ctx.Err() == nil {
			r.fail(fmt.Errorf("host %d stopped: %v", index, err))
		}
	}()
	// The dial permit is consumed before the dependency starts waiting on
	// remote registration. Key generation and intentional pacing are excluded.
	select {
	case began = <-proxy.dialStarted:
	case err := <-h.done:
		h.done <- err
		return fmt.Errorf("host startup: %w", err)
	case <-r.ctx.Done():
		return context.Cause(r.ctx)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case status := <-ready:
		if status != "ready" {
			return fmt.Errorf("host readiness is %s", status)
		}
	case err := <-h.done:
		h.done <- err
		return fmt.Errorf("host startup: %w", err)
	case <-timer.C:
		return errors.New("host readiness deadline")
	case <-r.ctx.Done():
		return context.Cause(r.ctx)
	}
	r.rec.mu.Lock()
	r.rec.summary.EstablishedHosts++
	r.rec.mu.Unlock()
	h.mu.Lock()
	s := h.initial
	h.mu.Unlock()
	r.rec.event("host_ready", map[string]any{"host": index, "transport": u.Scheme, "node": s.NodeAddr, "session_id": s.SessionId, "ready_ms": float64(time.Since(began)) / float64(time.Millisecond), "queue_ms": float64(permit.queued) / float64(time.Millisecond)})
	return nil
}
func (r *runState) admit(identity ssh.Signer) error {
	// One fresh in-memory guest identity belongs to this run, independent of
	// host registration, host session and relay keys. Reconnects retain it.
	var err error
	r.guestIdentity, err = makeSigner()
	if err != nil {
		return err
	}
	ht, _ := r.cfg.target(r.cfg.HostTarget)
	et, _ := r.cfg.target(r.cfg.EntryTarget)
	r.hosts = make([]*hostRun, r.cfg.Hosts)
	if err := r.admissions(r.cfg.Hosts, func(i int) error { return r.startHost(i, ht, identity) }); err != nil {
		return err
	}
	for _, h := range r.hosts {
		for j := 0; j < r.cfg.GuestsPerHost; j++ {
			id := len(r.guests)
			total := r.cfg.Hosts * r.cfg.GuestsPerHost
			// Select guests from the opposite end so a 50/50 mix crosses host transports.
			u, err := transport(et, r.cfg.GuestWSPercent, total-1-id, total, r.cfg.EntryPublic)
			if err != nil {
				return err
			}
			proxy, err := newTunnelProxy(r.ctx, r.guard, et)
			if err != nil {
				return err
			}
			r.proxies = append(r.proxies, proxy)
			q := &guest{id: id, host: h, target: et, endpoint: u, identity: r.guestIdentity, proxy: proxy}
			r.clientsMu.Lock()
			r.guests = append(r.guests, q)
			r.clientsMu.Unlock()
		}
	}
	if err := r.admissions(len(r.guests), func(i int) error {
		q := r.guests[i]
		began := time.Now()
		if err := q.connect(r.ctx, r); err != nil {
			return err
		}
		r.rec.mu.Lock()
		r.rec.summary.EstablishedGuests++
		r.rec.summary.EstablishedChannels += len(q.channels)
		r.rec.mu.Unlock()
		r.rec.event("admission", map[string]any{"role": "guest", "guest": q.id, "ready_ms": float64(time.Since(began)-q.queueElapsed) / float64(time.Millisecond), "queue_ms": float64(q.queueElapsed) / float64(time.Millisecond)})
		return nil
	}); err != nil {
		return err
	}
	if r.cfg.idleHostOnly() {
		return r.hostCanary(0)
	}
	return nil
}
func (r *runState) cleanup() error {
	r.cancel(context.Canceled)
	r.activeWorkers.Wait()
	r.workers.Wait()
	for _, q := range r.guests {
		q.setExpected(true)
		q.close()
	}
	for _, p := range r.proxies {
		p.close()
	}
	var rootErr error
	for _, h := range r.hosts {
		if h != nil {
			hostErr := <-h.done
			_ = hostErr // Exit errors were classified before this cancellation/join.
			if h.h.SFTPRoot != nil {
				if h.started {
					ctx, cancel := context.WithTimeout(context.Background(), finalDrainLimit)
					err := h.h.WaitSFTP(ctx)
					cancel()
					if err != nil {
						rootErr = errors.Join(rootErr, fmt.Errorf("host %d SFTP workers did not join; retained transfer root and directory: %w", h.id, err))
						continue
					}
				}
				rootErr = errors.Join(rootErr, h.h.SFTPRoot.Close())
			}
		}
	}
	// A timed-out filesystem/permission worker may still reference the root.
	// Never let the parent RemoveAll bypass that failed lifetime proof.
	if rootErr != nil {
		return rootErr
	}
	if err := os.RemoveAll(r.dir); err != nil {
		return err
	}
	_, err := os.Stat(r.dir)
	complete := os.IsNotExist(err)
	r.rec.mu.Lock()
	r.rec.summary.CleanupComplete = complete
	r.rec.mu.Unlock()
	if !complete {
		return errors.New("temporary directory still exists after cleanup")
	}
	return nil
}

func watchFiles(c Config, now time.Time) error {
	if c.WatchdogFile != "" {
		if _, err := os.Stat(c.WatchdogFile); err == nil {
			return errors.New("external_watchdog_stop")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if c.WatchdogHeartbeatFile != "" {
		info, err := os.Stat(c.WatchdogHeartbeatFile)
		if err != nil || now.Sub(info.ModTime()) > 30*time.Second || info.ModTime().After(now.Add(time.Second)) {
			return errors.New("external_watchdog_heartbeat_lost")
		}
	}
	return nil
}
func (r *runState) telemetry() {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		clients := map[string]*http.Client{}

		for _, t := range r.cfg.Manifest.Targets {
			target := t
			tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return r.guard.connect(ctx, target, addr)
			}}
			defer tr.CloseIdleConnections()
			tr.ResponseHeaderTimeout = 3 * time.Second
			clients[t.MachineID] = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("telemetry redirect refused") }}
			r.telemetryMu.Lock()
			r.lastTelemetry[t.MachineID] = time.Now()
			r.telemetryMu.Unlock()
		}
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		collect := func() {
			for _, t := range r.cfg.Manifest.Targets {
				req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, t.TelemetryURL, nil)
				if err != nil {
					r.fail(err)
					return
				}
				resp, err := clients[t.MachineID].Do(req)
				if err == nil {
					bodyTimer := time.AfterFunc(3*time.Second, func() { _ = resp.Body.Close() })
					body, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
					_ = resp.Body.Close()
					bodyTimer.Stop()
					if e == nil && resp.StatusCode == 200 && len(body) <= 1<<20 {
						r.telemetryMu.Lock()
						r.lastTelemetry[t.MachineID] = time.Now()
						r.telemetryMu.Unlock()
						r.rec.event("relay_metrics", map[string]any{"machine_id": t.MachineID, "prometheus": string(body)})
					} else {
						err = errors.New("invalid telemetry response")
					}
				}
				if err != nil {
					r.rec.event("telemetry_error", map[string]any{"machine_id": t.MachineID, "error": err.Error()})
				}

			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fields := map[string]any{"pid": os.Getpid(), "goroutines": runtime.NumGoroutine(), "heap_alloc": m.HeapAlloc, "heap_sys": m.HeapSys, "go_sys": m.Sys, "gc_count": m.NumGC, "go_version": runtime.Version()}
			if status, err := os.ReadFile("/proc/self/status"); err == nil {
				fields["proc_status"] = string(status)
			}
			if stat, err := os.ReadFile("/proc/self/stat"); err == nil {
				fields["proc_stat"] = string(stat)
			}
			r.rec.event("generator", fields)
		}
		collect()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-tick.C:
				collect()
			}
		}
	}()
}

func Run(ctx context.Context, c Config, out io.Writer) (result Summary, err error) {
	if err = c.Validate(time.Now()); err != nil {
		return result, err
	}
	if err = watchFiles(c, time.Now()); err != nil {
		return result, err
	}
	rec := newRecorder(out, c)
	started := time.Now()
	deadline := c.Manifest.ExpiresAt
	bounded, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	runctx, cancel := context.WithCancelCause(bounded)
	rec.fail = cancel
	r := &runState{lastTelemetry: map[string]time.Time{}, cfg: c, guard: newGuard(c), rec: rec, ctx: runctx, cancel: cancel}
	r.helper = c.HelperExecutable
	if r.helper == "" {
		r.helper, err = os.Executable()
		if err != nil {
			return result, err
		}
	}
	r.dir, err = os.MkdirTemp("", "upterm-cap-")
	if err != nil {
		return result, err
	}
	defer func() {
		if e := r.cleanup(); e != nil {
			err = errors.Join(err, e)
			rec.mu.Lock()
			rec.summary.StopReason = "cleanup_failure"
			rec.mu.Unlock()
		}
		rec.mu.Lock()
		r.guard.mu.Lock()
		rec.summary.PeakExternalConnections = r.guard.peak
		r.guard.mu.Unlock()
		rec.summary.DurationSeconds = time.Since(started).Seconds()
		sort.Float64s(rec.summary.RTTMillis)
		samples := rec.summary.RTTMillis
		if len(samples) > 0 {
			rec.summary.RTTP50Millis = samples[(len(samples)-1)*50/100]
			rec.summary.RTTP95Millis = samples[(len(samples)-1)*95/100]
			rec.summary.RTTP99Millis = samples[(len(samples)-1)*99/100]
		}
		result = rec.summary
		rec.mu.Unlock()
		rec.event("summary", map[string]any{"summary": result})
		if rec.err != nil {
			err = errors.Join(err, rec.err)
			result.DeliveryComplete = false
			if result.StopReason != "cleanup_failure" {
				result.StopReason = rec.err.Error()
			}
		}
	}()
	rec.event("phase_start", map[string]any{"config": safeConfig(c), "input_frame_bytes": 128, "host_output_frame_bytes": 1024, "framing_header_bytes": 44, "framing_newline_bytes": 1, "wire_overhead": "not measured", "duration_includes_admission": false})
	var identity ssh.Signer
	if c.HostIdentityFile != "" {
		key, e := os.ReadFile(c.HostIdentityFile)
		if e != nil {
			err = errors.New("cannot read host identity")
		} else {
			identity, e = ssh.ParsePrivateKey(key)
			if e != nil {
				err = errors.New("invalid host identity")
			}
		}
		if err != nil {
			rec.summary.StopReason = "identity_error"
			return result, err
		}
	}
	if err = r.reserve(c.hostOutputReservation()); err != nil {
		rec.summary.StopReason = "payload_budget"
		return result, err
	}
	r.telemetry()
	r.watch()
	admissionTimer := time.AfterFunc(time.Duration(c.Hosts*(1+c.GuestsPerHost))*time.Second/time.Duration(c.AdmissionsPerSecond)+30*time.Second, func() { r.fail(errors.New("admission_deadline")) })
	defer admissionTimer.Stop()
	if err = r.admit(identity); err != nil {
		rec.mu.Lock()
		rec.summary.AdmissionFailures++
		rec.summary.StopReason = "admission_failure"
		rec.mu.Unlock()
		return result, err
	}
	admissionTimer.Stop()
	steadyStarted := time.Now()
	rec.mu.Lock()
	rec.summary.SetupSeconds = steadyStarted.Sub(started).Seconds()
	rec.mu.Unlock()
	steady := time.NewTimer(time.Duration(c.DurationSeconds) * time.Second)
	defer steady.Stop()
	defer func() {
		rec.mu.Lock()
		rec.summary.SteadySeconds = min(time.Since(steadyStarted).Seconds(), float64(c.DurationSeconds))
		rec.mu.Unlock()
	}()
	rec.event("steady_start", map[string]any{"duration_seconds": c.DurationSeconds})
	if c.idleHostOnly() {
		r.canaries()
	}
	r.activeWorkload(steadyStarted, &r.activeWorkers)
	if c.TransferConcurrency > 0 {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			if e := r.transfers(); e != nil {
				r.fail(e)
			}
		}()
	}
	if c.ChurnPercent > 0 {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			if e := r.churn(); e != nil {
				r.fail(e)
			}
		}()
	}
	for {
		select {
		case <-runctx.Done():
			err = context.Cause(runctx)
			rec.mu.Lock()
			rec.summary.StopReason = err.Error()
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				rec.summary.StopReason = "manifest_expired"
			}
			rec.mu.Unlock()
			return result, err
		case <-steady.C:
			rec.event("steady_end", map[string]any{"duration_seconds": c.DurationSeconds})
			drainStarted := time.Now()
			// This independent bound also closes transports beneath a blocked final
			// input/barrier write. Manifest expiry and all safety watches stay active.
			drain := time.AfterFunc(finalDrainLimit, func() { r.fail(errors.New("terminal_delivery_timeout")) })
			r.activeWorkers.Wait()
			if runctx.Err() == nil {
				err = r.completeDelivery()
			}
			drain.Stop()
			if runctx.Err() != nil {
				err = context.Cause(runctx)
			}
			rec.mu.Lock()
			rec.summary.DrainSeconds = time.Since(drainStarted).Seconds()
			if err == nil && c.TransferConcurrency > 0 && rec.summary.Transfers != c.TransferConcurrency {
				err = errors.New("incomplete_transfers")
			}
			if err == nil && c.ChurnPercent > 0 && !rec.summary.ChurnCompleted {
				err = errors.New("incomplete_churn")
			}
			if err == nil && c.Active && rec.summary.ActiveFrames+rec.summary.PausedActiveFrames != int64(c.Hosts*c.GuestsPerHost*c.DurationSeconds) {
				err = errors.New("offered_workload_incomplete")
			}
			rec.summary.StopReason = "duration"
			rec.summary.DeliveryComplete = err == nil
			if err != nil {
				rec.summary.StopReason = err.Error()
			}
			rec.mu.Unlock()
			rec.event("delivery_complete", map[string]any{"complete": err == nil, "drain_seconds": time.Since(drainStarted).Seconds()})
			return result, err
		}
	}
}

func safeConfig(c Config) any {
	copy := c
	copy.Manifest = Manifest{}
	copy.HostIdentityFile = ""
	copy.HelperExecutable = ""
	return copy
}
func telemetryLost(last, now time.Time) bool { return now.Sub(last) > 30*time.Second }
func (r *runState) watch() {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case now := <-tick.C:
				if err := watchFiles(r.cfg, now); err != nil {
					r.fail(err)
					return
				}
				r.telemetryMu.Lock()
				lost := false
				for _, last := range r.lastTelemetry {
					lost = lost || telemetryLost(last, now)
				}
				r.telemetryMu.Unlock()
				if lost {
					r.fail(errors.New("telemetry_lost"))
					return
				}
				r.clientsMu.RLock()
				guests := append([]*guest(nil), r.guests...)
				r.clientsMu.RUnlock()
				for _, q := range guests {
					q.mu.Lock()
					stale := false
					if !q.expected {
						for _, sent := range q.pending {
							stale = stale || now.Sub(sent) > 10*time.Second
						}
					}
					q.mu.Unlock()
					if stale {
						r.fail(errors.New("terminal_response_timeout"))
						return
					}
				}
				r.rec.mu.Lock()
				err := r.rec.err
				r.rec.mu.Unlock()
				if err != nil {
					r.fail(err)
					return
				}
			}
		}
	}()
}
func (r *runState) admissions(count int, work func(int) error) error {
	if count == 0 {
		return r.ctx.Err()
	}
	workers := min(count, 20)
	jobs := make(chan int)
	failed := make(chan error, 1)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-r.ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					if err := work(index); err != nil {
						select {
						case failed <- err:
						default:
						}
						r.fail(err)
						return
					}
				}
			}
		}()
	}
offer:
	for i := 0; i < count; i++ {
		select {
		case jobs <- i:
		case <-r.ctx.Done():
			break offer
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-failed:
		return err
	default:
		return context.Cause(r.ctx)
	}
}
