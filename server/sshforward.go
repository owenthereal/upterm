// Adapted from github.com/cmoog/sshproxy/reverseproxy.go.
//
// MIT License
//
// Copyright (c) 2021 Charles Moog
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshPeer keeps the raw request and channel streams returned by NewServerConn
// or NewClientConn. Wrapping these in ssh.Client would consume global requests
// and reject unregistered channel types before the forwarder could see them.
type sshPeer struct {
	conn     ssh.Conn
	channels <-chan ssh.NewChannel
	requests <-chan *ssh.Request
}

// An ordinary peer disconnect gets a bounded opportunity to deliver data
// already buffered by SSH. A consumer stalled beyond this grace can lose the
// remaining bytes. This deadline does not apply to live transports or EOF;
// explicit cancellation, shutdown and queue overflow always interrupt it.
const sshForwardDrainTimeout = 5 * time.Second

// A stalled channel whose source has closed is bounded, but how far the bound
// may escalate depends on whose connection it is.
type sshAbortScope int

const (
	// abortChannel closes the stalled channel and stops there. This is the
	// scope for a host connection, whose transport carries the reverse tunnel
	// every guest's traffic rides: tearing it down over one stalled channel
	// would end the session for everyone attached.
	abortChannel sshAbortScope = iota

	// abortConnection may additionally cancel the forwarder, closing both
	// transports. This is the scope for a guest connection, which is that one
	// guest's: forwardSSH runs per accepted downstream connection with its own
	// dialed upstream, so cancelling ends that guest and nothing else.
	//
	// Nothing else, but not nothing: it ends every channel on that connection,
	// not just the stalled one, and ends them abruptly. The escalation fires
	// while both transports are still live, so closedPeer stays -1 above and
	// forwardSSH skips its drain loop entirely — the other channels lose
	// whatever SSH had buffered for them, with no grace at all. Weigh that
	// against sshForwardChannelDrainTimeout before shortening it.
	abortConnection
)

const (
	// sshForwardChannelDrainTimeout bounds how long a direction whose source
	// has closed may stay blocked writing to a destination that has stopped
	// reading, on a connection that is otherwise live. It carries the same
	// trade-off as sshForwardDrainTimeout: a consumer stalled beyond the grace
	// can lose bytes it had not yet received.
	//
	// The two are equal by coincidence of judgement, not by design, and nothing
	// should be read into the match. They never apply at once —
	// abortStalledDirection stands down as soon as the connection starts
	// draining — and that separation is deliberate: when both were armed on one
	// stall, which fired first decided which error the shutdown reported.
	//
	// It bounds total drain time, not lack of progress: a destination draining
	// steadily but slowly is treated exactly like one that stopped, because the
	// copy below is a plain io.Copy and reports nothing until it finishes. So
	// this is also the deadline by which a merely slow consumer is declared
	// stalled — five seconds of real drain is the budget, not five seconds of
	// silence.
	sshForwardChannelDrainTimeout = 5 * time.Second

	// sshForwardChannelAbortGrace is how long the CLOSE sent after that has to
	// take effect. A peer that is reading its socket at all answers a CLOSE in
	// microseconds; one that does not is not reading the socket either, and
	// only transport teardown can release the write.
	//
	// What follows the grace is the expensive step, and only on a guest
	// connection: abortConnection cancels the forwarder, which takes down every
	// other channel on that connection without draining any of them. The grace
	// is short because a peer that has not answered by now will not, not
	// because the next step is cheap.
	sshForwardChannelAbortGrace = time.Second
)

var errSSHChannelDrainStalled = errors.New("ssh: channel drain stalled after source close")

// forwardSSH owns both authenticated connections and joins all workers before
// returning. Ordinary transport completion first drains received channel data
// and request tails toward the surviving peer; forced cancellation closes both
// transports immediately to release blocked opens, requests and writes.
func forwardSSH(ctx context.Context, downstream, upstream sshPeer, scope sshAbortScope) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	draining := make(chan struct{})
	forwarder := sshForwarder{
		ctx:          ctx,
		cancel:       cancel,
		scope:        scope,
		draining:     draining,
		drainTimeout: sshForwardChannelDrainTimeout,
		abortGrace:   sshForwardChannelAbortGrace,
	}
	var workers sync.WaitGroup
	type peerExit struct {
		index int
		err   error
	}
	exited := make(chan peerExit, 2)
	channelsDone := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	requestsDone := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	peers := []sshPeer{downstream, upstream}
	for i, source := range peers {
		destination := peers[1-i]
		workers.Go(func() { exited <- peerExit{i, source.conn.Wait()} })
		workers.Go(func() { forwarder.channels(destination.conn, source.channels, draining, channelsDone[i]) })
		workers.Go(func() {
			finished := sync.OnceFunc(func() { close(requestsDone[i]) })
			defer finished()
			// A disconnected source cannot receive an outstanding global reply. Do
			// not hold up drain completion on that reply, but still drain all channel
			// buffers before closing the destination transport to release its sender.
			// Zero grace: finished only signals drain completion, it writes nothing.
			forwarder.requests(destination.conn, source.requests, nil, finished, 0, nil)
		})
	}
	var err error
	closedPeer := -1
	select {
	case <-ctx.Done():
		err = context.Cause(ctx)
	case exit := <-exited:
		closedPeer, err = exit.index, exit.err
	}
	close(draining)
	if closedPeer >= 0 {
		timer := time.NewTimer(sshForwardDrainTimeout)
		firstChannels, secondChannels := channelsDone[0], channelsDone[1]
		sourceRequests := requestsDone[closedPeer]
	drain:
		for firstChannels != nil || secondChannels != nil || sourceRequests != nil {
			select {
			case <-firstChannels:
				firstChannels = nil
			case <-secondChannels:
				secondChannels = nil
			case <-sourceRequests:
				sourceRequests = nil
			case <-ctx.Done():
				err = context.Cause(ctx)
				break drain
			case <-exited:
				break drain // Neither transport can receive more data.
			case <-timer.C:
				err = errors.New("ssh: buffered data drain timed out")
				break drain
			}
		}
		timer.Stop()
	}
	cancel(err)
	_ = downstream.conn.Close()
	_ = upstream.conn.Close()
	workers.Wait()
	return err
}

type sshForwarder struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	scope  sshAbortScope

	// draining closes when the connection starts shutting down, which is what
	// hands the stalled-channel bound over to forwardSSH. Nil in tests that
	// exercise a single direction, where nothing else owns that bound.
	draining <-chan struct{}

	// Fields rather than direct reads of the constants above, so tests can run
	// the watchdog on a timescale that does not dominate the suite.
	drainTimeout time.Duration
	abortGrace   time.Duration
}

// A peer can pipeline channel opens without waiting for confirmation, and each
// one still awaiting the destination costs a goroutine blocked in OpenChannel,
// so cap how many opens are outstanding at once. Over the cap opens are refused
// rather than queued: blocking this loop would stall the mux for every other
// channel on the connection, and the request path is bounded for the same
// reason. This bounds opens in progress only — an established channel holds no
// permit, so the count of live channels stays as unlimited as SSH itself.
const maxSSHConcurrentChannelOpens = 64

// Once draining starts, stop opening channels and report completion of the
// accepted channels independently of connection Wait. Keep rejecting incoming
// opens until transport shutdown so the surviving mux never loses its reader.
func (f sshForwarder) channels(destination ssh.Conn, channels <-chan ssh.NewChannel, draining <-chan struct{}, done chan struct{}) {
	var workers sync.WaitGroup
	var accepted sshChannelDrain
	defer workers.Wait()
	finish := func() { accepted.wait(); close(done) }
	opens := make(chan struct{}, maxSSHConcurrentChannelOpens)
	for {
		select {
		case <-draining:
			go finish()
			for channel := range channels {
				_ = channel.Reject(ssh.ConnectionFailed, "SSH peer disconnected")
			}
			<-done
			return
		case channel, ok := <-channels:
			if !ok {
				finish()
				return
			}
			select {
			case opens <- struct{}{}:
			default:
				_ = channel.Reject(ssh.ResourceShortage, "too many concurrent channel opens")
				continue
			}
			workers.Go(func() {
				f.channel(destination, channel, &accepted, func() { <-opens })
			})
		}
	}
}

// Pending channel opens have no accepted data to drain. Track accepted
// channels separately so an unanswered open cannot delay ordinary shutdown.
// The lock prevents new registrations after wait begins, including when an
// in-flight OpenChannel succeeds just as its source disconnects.
type sshChannelDrain struct {
	mu      sync.Mutex
	closing bool
	workers sync.WaitGroup
}

func (d *sshChannelDrain) start() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		return false
	}
	d.workers.Add(1)
	return true
}

func (d *sshChannelDrain) wait() {
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()
	d.workers.Wait()
}

// openDone releases the permit this open holds. It fires as soon as the open
// resolves either way, so the cap counts opens in progress rather than the
// channels they establish — a guest holding a channel open must not consume a
// permit for the life of its session.
func (f sshForwarder) channel(destination ssh.Conn, incoming ssh.NewChannel, accepted *sshChannelDrain, openDone func()) {
	openDone = sync.OnceFunc(openDone)
	defer openDone()
	// Accept only after the destination accepts, preserving CHANNEL_OPEN_FAILURE.
	remote, remoteRequests, err := destination.OpenChannel(incoming.ChannelType(), incoming.ExtraData())
	if err != nil {
		var rejection *ssh.OpenChannelError
		if errors.As(err, &rejection) {
			_ = incoming.Reject(rejection.Reason, rejection.Message)
		} else {
			_ = incoming.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	if !accepted.start() {
		_ = incoming.Reject(ssh.ConnectionFailed, "SSH peer disconnected")
		_ = remote.Close()
		ssh.DiscardRequests(remoteRequests)
		return
	}
	defer accepted.workers.Done()
	local, localRequests, err := incoming.Accept()
	if err != nil {
		_ = remote.Close()
		// Even a failed accept must service the already-opened peer's requests.
		ssh.DiscardRequests(remoteRequests)
		return
	}
	openDone() // established: the channel itself holds no permit
	localEndpoint := &sshForwardChannel{Channel: local}
	remoteEndpoint := &sshForwardChannel{Channel: remote}
	var workers sync.WaitGroup
	workers.Go(func() { f.channelDirection(localEndpoint, remoteEndpoint, remoteRequests) })
	workers.Go(func() { f.channelDirection(remoteEndpoint, localEndpoint, localRequests) })
	workers.Wait()
}

// replies protects replies owed to this endpoint from an ordinary close sent
// by the opposite direction. Cancellation and unanswered-request aborts bypass
// it so they can release blocked senders while request ingress keeps draining.
type sshForwardChannel struct {
	ssh.Channel
	replies sync.Mutex
}

// channelDirection forwards one direction of one channel. It preserves:
//
//   - Byte order within each stream. stdin, stdout and stderr are each a
//     single io.Copy in copySSHChannel.
//   - Request order within this direction. requests dispatches from one serial
//     sender, so replies come back in the order the requests were sent, as
//     RFC 4254 section 4 requires.
//   - Forwarded data before CLOSE, on the ordinary path. requests returns,
//     then streams.Wait(), and only then destination.Close(). Every forwarded
//     byte has returned from its Write before CLOSE is written, and x/crypto
//     serializes channel packets and refuses writes once CLOSE has gone out,
//     so a peer reading until CHANNEL_CLOSE is not truncated here. The aborts
//     are the exception: abortPending closes destination from inside requests,
//     before streams.Wait(); abortStalledDirection closes it from a watchdog
//     once the source has closed and the copy has not drained within
//     sshForwardChannelDrainTimeout; and cancellation, request-queue overflow
//     and sshForwardDrainTimeout close both transports outright. Each of those
//     can cut a Write that has not returned, and copySSHChannel discards the
//     error.
//   - EOF before CLOSE, and half-close survives. See copySSHChannel.
//
// It does not preserve the relative order of ordinary data, extended data and
// requests, and cannot: that information is already gone when we see it.
// x/crypto delivers incoming requests on a buffered Go channel (chanSize = 16,
// handshake.go:26 at v0.55.0) while data lands in a byte buffer, so its mux
// read loop runs ahead and buffers post-request bytes before the request is
// dequeued. Nothing ties a
// request to an offset in the byte stream, so sequencing here would order
// goroutine observations rather than recover packet order. Callers that need
// a resize applied before subsequent stdin cannot get it from the proxy alone;
// the host applies window events and copies stdin in separate actors.
//
// Normal close waits until source data and requests have drained. An explicit
// source CLOSE can instead abort a pending reply (see requests below). In
// particular, EOF alone cannot close a channel: a command may still produce
// output and status after stdin EOF. Treat either endpoint's CLOSE
// symmetrically so a caller can close one channel without leaving its peer
// open for the connection's lifetime.
//
// That symmetry is not enough on its own when the destination has stopped
// reading: the copy below stays blocked in its Write, so the close at the end
// is never reached and the pair is stranded for the connection's lifetime.
// abortStalledDirection bounds it.
func (f sshForwarder) channelDirection(destination, source *sshForwardChannel, requests <-chan *ssh.Request) {
	finished := make(chan struct{})
	defer close(finished)
	sourceClosed := make(chan struct{})
	go f.abortStalledDirection(destination, sourceClosed, finished)

	var streams sync.WaitGroup
	streams.Go(func() { copySSHChannel(destination, source) })
	f.requests(sshChannelRequestSender{destination}, requests,
		sync.OnceFunc(func() { close(sourceClosed) }),
		func() { _ = destination.Close() }, sshRequestAbortGrace, &source.replies)
	streams.Wait()
	// The source may send success and CLOSE back-to-back. Its reply worker
	// must deliver that success before this direction closes the destination.
	destination.replies.Lock()
	defer destination.replies.Unlock()
	_ = destination.Close()
}

// abortStalledDirection releases a direction whose source has closed but whose
// destination has stopped accepting bytes.
//
// It is a watchdog rather than a step in the teardown because every step of
// that teardown is itself a transport write a stalled peer can block. Close
// marshals CHANNEL_CLOSE and calls writePacket, which takes the channel's write
// mutex and writes to the transport — the same mutex a blocked Write already
// holds — so a sequential abort would never reach its own timer in the case it
// exists for. requests has the same problem one step earlier, behind two
// barriers rather than one: a request still dispatched to that blocked sender
// keeps active non-nil, so its loop does not even reach its own exit condition
// while completed never fires, and past the loop its deferred wait for the
// sender would hold it anyway. Neither barrier lifts until the write does.
//
// It stands down the moment the connection itself begins draining, because
// from there forwardSSH's own bound owns the stall: it allows
// sshForwardDrainTimeout for the channel buffers and then closes both
// transports, which releases a blocked write more thoroughly than closing one
// channel does. Two bounds on the same stall would otherwise race — they are
// armed within moments of each other and, before this, ran on identical
// timeouts — and the winner decides which error the shutdown reports. The
// transport's is the one callers are contracted to see.
func (f sshForwarder) abortStalledDirection(destination ssh.Channel, sourceClosed, finished <-chan struct{}) {
	select {
	case <-finished:
		return
	case <-f.ctx.Done():
		return
	case <-f.draining:
		return
	case <-sourceClosed:
	}
	if f.settledWithin(finished, f.drainTimeout) {
		return
	}
	// In its own goroutine, for the reason above. A write blocked on an
	// exhausted window does not hold the channel's write mutex, so this is
	// enough whenever the peer is still reading its socket: it answers the
	// CLOSE, and x/crypto's channel teardown fails the pending write.
	go func() { _ = destination.Close() }()
	if f.settledWithin(finished, f.abortGrace) {
		return
	}
	if f.scope == abortConnection {
		f.cancel(errSSHChannelDrainStalled)
	}
}

// settledWithin reports whether this direction finished, the connection began
// draining, or the context was cancelled before timeout elapsed — the three
// ways the watchdog stops being the thing that has to act.
func (f sshForwarder) settledWithin(finished <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-finished:
		return true
	case <-f.draining:
		return true
	case <-f.ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

// copySSHChannel copies ordinary data and extended data concurrently, so byte
// order holds within each stream but not between them. See channelDirection.
//
// EOF covers both ordinary and extended data; sending it before stderr drains
// would make subsequent stderr writes fail. CloseWrite preserves the other
// direction, including output produced after the caller finishes writing stdin.
func copySSHChannel(destination, source ssh.Channel) {
	var streams sync.WaitGroup
	streams.Go(func() { _, _ = io.Copy(destination, source) })
	_, _ = io.Copy(destination.Stderr(), source.Stderr())
	streams.Wait()
	_ = destination.CloseWrite()
}

type sshRequestSender interface {
	SendRequest(string, bool, []byte) (bool, []byte, error)
}

type sshChannelRequestSender struct{ ssh.Channel }

func (s sshChannelRequestSender) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	ok, err := s.Channel.SendRequest(name, wantReply, payload)
	return ok, nil, err
}

// A peer can send requests without SSH flow control while a reply is pending.
// Bound retained requests per direction; overflow closes the connection rather
// than blocking ingress (which would also block the mux's shutdown path).
const (
	maxSSHQueuedRequests     = 256
	maxSSHQueuedRequestBytes = 1 << 20
)

// sshRequestAbortGrace is how long a destination still has to answer a request
// whose source has since disappeared, before the sender waiting on that answer
// is forced free. For a channel direction the release is a CLOSE, and x/crypto
// offers no way to observe that SendRequest has written its packet, so the
// grace is also what keeps that CLOSE from overtaking the request it follows.
// A destination with an answer to give sends it in microseconds.
const sshRequestAbortGrace = 100 * time.Millisecond

// sshRequestJob carries one request to the serial sender. awaitReply is cleared
// when the source is already gone: nobody is left to receive the reply, and a
// send that does not wait for one returns as soon as its packet is written, so
// the CLOSE that ends the direction cannot overtake it.
type sshRequestJob struct {
	request    *ssh.Request
	awaitReply bool
}

// requests keeps reading ingress independently of its single serial sender.
// Closing a transport alone cannot release SendRequest when the mux is stuck
// delivering an incoming request, so ingress continues draining on cancellation.
//
// A source that disappears leaves nobody able to receive a reply. Requests
// dispatched after that point are sent without awaiting one, so they complete
// as soon as they are written and the whole tail still drains in order. Only a
// reply already being awaited when the source went away needs abortPending,
// after sshRequestAbortGrace: for channels it closes the destination channel,
// for globals it waives waiting for the reply during transport drain. Pass a
// zero grace where abortPending writes nothing to the wire.
//
// sourceClosed, which may be nil, fires once when incoming closes: the point at
// which the source can send nothing further. It is distinct from abortPending,
// which fires only when a reply was outstanding at that moment, and it is
// reported from the ingress loop rather than on return, because the serial
// sender may still be blocked writing to a destination that has stopped
// reading. A caller that needs to bound such a destination cannot wait for this
// function to return. It runs synchronously on the ingress loop's goroutine, so
// a slow sourceClosed delays further dispatch and cancellation handling until
// it returns.
func (f sshForwarder) requests(destination sshRequestSender, incoming <-chan *ssh.Request, sourceClosed func(), abortPending func(), grace time.Duration, replies *sync.Mutex) {
	jobs := make(chan sshRequestJob)
	completed := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for job := range jobs {
			request := job.request
			locked := job.awaitReply && replies != nil
			if locked {
				replies.Lock()
			}
			ok, payload, err := destination.SendRequest(request.Type, job.awaitReply, request.Payload)
			if err != nil {
				ok, payload = false, nil
			}
			// Clear the pending-reply state before replying to the source: once
			// it receives success, it may immediately send exit-status and CLOSE.
			completed <- struct{}{}
			// Only a reply that was actually awaited can be relayed: once the
			// source is gone the request goes out without want_reply, and there
			// is no answer to pass back and nobody left to receive one.
			if job.awaitReply {
				_ = request.Reply(ok, payload)
			}
			if locked {
				replies.Unlock()
			}
		}
	}()
	defer func() { close(jobs); <-senderDone }()

	var queue []*ssh.Request
	var active *ssh.Request
	awaitingReply := false
	queuedBytes := 0
	cancelled := f.ctx.Done()
	stopping := false
	var abortTimer *time.Timer
	var abortAfter <-chan time.Time
	disarmAbort := func() {
		if abortTimer != nil {
			abortTimer.Stop()
			abortTimer, abortAfter = nil, nil
		}
	}
	defer disarmAbort()
	for incoming != nil || active != nil || len(queue) > 0 {
		var send chan<- sshRequestJob
		var next sshRequestJob
		if active == nil && len(queue) > 0 {
			send = jobs
			next = sshRequestJob{request: queue[0], awaitReply: queue[0].WantReply && incoming != nil}
		}
		select {
		case request, ok := <-incoming:
			if !ok {
				incoming = nil
				if sourceClosed != nil {
					sourceClosed()
				}
				// The reply this send is waiting on can no longer be delivered.
				// Let the destination answer anyway if it is merely slow; the
				// same wait puts the request write safely ahead of the CLOSE
				// abortPending may send.
				if awaitingReply && abortPending != nil {
					if grace <= 0 {
						abortPending()
					} else {
						abortTimer = time.NewTimer(grace)
						abortAfter = abortTimer.C
					}
				}
				continue
			}
			if stopping {
				continue
			}
			size := len(request.Type) + len(request.Payload)
			if len(queue) == maxSSHQueuedRequests || queuedBytes+size > maxSSHQueuedRequestBytes {
				f.cancel(errors.New("ssh: request queue limit exceeded"))
				stopping, queue, queuedBytes = true, nil, 0
				continue
			}
			queue = append(queue, request)
			queuedBytes += size
		case send <- next:
			active, awaitingReply = next.request, next.awaitReply
			queue[0] = nil
			queue = queue[1:]
			queuedBytes -= len(active.Type) + len(active.Payload)
		case <-completed:
			active, awaitingReply = nil, false
			disarmAbort()
		case <-abortAfter:
			disarmAbort()
			abortPending()
		case <-cancelled:
			// Discard queued work, but keep consuming ingress until the mux closes it.
			// The connection owner closes both transports to release the active send.
			stopping, queue, queuedBytes = true, nil, 0
			cancelled = nil
		}
	}
}

// rejectSSHChannels reports an upstream failure after downstream authentication
// succeeded. The caller supplies a bounded context; while waiting for the first
// channel, global requests are answered with the cause so they cannot freeze
// the SSH mux and so peers that speak before opening a channel still learn why.
// It owns downstream and returns after closing it and joining its workers.
func rejectSSHChannels(ctx context.Context, downstream sshPeer, cause error) error {
	var workers sync.WaitGroup
	finished := make(chan struct{})
	workers.Go(func() {
		select {
		case <-ctx.Done():
			_ = downstream.conn.Close()
		case <-finished:
		}
	})
	// Not DiscardRequests: it answers (false, nil). A host opens no channel of
	// its own — it sends upterm:server-create-session first and prints the
	// failure reply body verbatim — so an empty body leaves it with no reason.
	// x/crypto carries this payload in SSH_MSG_REQUEST_FAILURE's trailing data.
	workers.Go(func() {
		for request := range downstream.requests {
			if request.WantReply {
				_ = request.Reply(false, []byte(cause.Error()))
			}
		}
	})
	defer func() {
		// Answer the opens the mux has already buffered while the transport is
		// still live. Past Close, Reject has no transport to write to and the
		// peer would see a bare disconnect in place of the reason. These are
		// writes, so a peer that has stopped reading can block them: the
		// deadline watcher above stays armed until the transport is closed,
		// because closing it is the only thing that releases such a write.
		rejectBufferedSSHChannels(downstream.channels, cause)
		_ = downstream.conn.Close()
		close(finished)
		// Release the mux's sender for opens that raced the close. These can no
		// longer be answered; draining them only unblocks shutdown.
		for range downstream.channels {
		}
		_ = downstream.conn.Wait()
		workers.Wait()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case channel, ok := <-downstream.channels:
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ok {
			return io.EOF
		}
		return channel.Reject(ssh.ConnectionFailed, cause.Error())
	}
}

// rejectBufferedSSHChannels answers the opens the mux has already queued
// without blocking on ones that may never arrive.
func rejectBufferedSSHChannels(channels <-chan ssh.NewChannel, cause error) {
	for {
		select {
		case channel, ok := <-channels:
			if !ok {
				return
			}
			_ = channel.Reject(ssh.ConnectionFailed, cause.Error())
		default:
			return
		}
	}
}
