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

// forwardSSH owns both authenticated connections and joins all workers before
// returning. Ordinary transport completion first drains received channel data
// and request tails toward the surviving peer; forced cancellation closes both
// transports immediately to release blocked opens, requests and writes.
func forwardSSH(ctx context.Context, downstream, upstream sshPeer) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	forwarder := sshForwarder{ctx: ctx, cancel: cancel}
	var workers sync.WaitGroup
	type peerExit struct {
		index int
		err   error
	}
	exited := make(chan peerExit, 2)
	draining := make(chan struct{})
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
			forwarder.requests(destination.conn, source.requests, finished, nil)
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
}

// Once draining starts, stop opening channels and report completion of the
// accepted channels independently of connection Wait. Keep rejecting incoming
// opens until transport shutdown so the surviving mux never loses its reader.
func (f sshForwarder) channels(destination ssh.Conn, channels <-chan ssh.NewChannel, draining <-chan struct{}, done chan struct{}) {
	var workers sync.WaitGroup
	var accepted sshChannelDrain
	defer workers.Wait()
	finish := func() { accepted.wait(); close(done) }
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
			workers.Go(func() { f.channel(destination, channel, &accepted) })
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

func (f sshForwarder) channel(destination ssh.Conn, incoming ssh.NewChannel, accepted *sshChannelDrain) {
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

// Normal close waits until source data and requests have drained. An explicit
// source CLOSE can instead abort a pending reply (see requests below). In particular, EOF
// alone cannot close a channel: a command may still produce output and status
// after stdin EOF. Treat either endpoint's CLOSE symmetrically so a caller can
// close one channel without leaving its peer open for the connection's lifetime.
func (f sshForwarder) channelDirection(destination, source *sshForwardChannel, requests <-chan *ssh.Request) {
	var streams sync.WaitGroup
	streams.Go(func() { copySSHChannel(destination, source) })
	f.requests(sshChannelRequestSender{destination}, requests, func() { _ = destination.Close() }, &source.replies)
	streams.Wait()
	// The source may send success and CLOSE back-to-back. Its reply worker
	// must deliver that success before this direction closes the destination.
	destination.replies.Lock()
	defer destination.replies.Unlock()
	_ = destination.Close()
}

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

// requests keeps reading ingress independently of its single serial sender.
// Closing a transport alone cannot release SendRequest when the mux is stuck
// delivering an incoming request, so ingress continues draining on cancellation.
// Source closure can abort an unanswered WantReply through abortPending. For
// channels it closes the destination channel; for globals it waives waiting for
// the reply during transport drain. Ordinary request tails still drain in order.
func (f sshForwarder) requests(destination sshRequestSender, incoming <-chan *ssh.Request, abortPending func(), replies *sync.Mutex) {
	jobs := make(chan *ssh.Request)
	completed := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for request := range jobs {
			if request.WantReply && replies != nil {
				replies.Lock()
			}
			ok, payload, err := destination.SendRequest(request.Type, request.WantReply, request.Payload)
			if err != nil {
				ok, payload = false, nil
			}
			// Clear the pending-reply state before replying to the source: once
			// it receives success, it may immediately send exit-status and CLOSE.
			completed <- struct{}{}
			if request.WantReply {
				_ = request.Reply(ok, payload)
				if replies != nil {
					replies.Unlock()
				}
			}
		}
	}()
	defer func() { close(jobs); <-senderDone }()

	var queue []*ssh.Request
	var active *ssh.Request
	queuedBytes := 0
	cancelled := f.ctx.Done()
	stopping := false
	for incoming != nil || active != nil || len(queue) > 0 {
		var send chan<- *ssh.Request
		var next *ssh.Request
		if active == nil && len(queue) > 0 {
			send, next = jobs, queue[0]
		}
		select {
		case request, ok := <-incoming:
			if !ok {
				incoming = nil
				if active != nil && active.WantReply && abortPending != nil {
					abortPending()
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
			active = next
			queue[0] = nil
			queue = queue[1:]
			queuedBytes -= len(next.Type) + len(next.Payload)
			if incoming == nil && active.WantReply && abortPending != nil {
				abortPending()
			}
		case <-completed:
			active = nil
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
// channel, global requests are rejected so they cannot freeze the SSH mux.
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
	workers.Go(func() { ssh.DiscardRequests(downstream.requests) })
	defer func() {
		close(finished)
		_ = downstream.conn.Close()
		// Drain channel opens buffered behind the first one during shutdown.
		for channel := range downstream.channels {
			_ = channel.Reject(ssh.ConnectionFailed, cause.Error())
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
