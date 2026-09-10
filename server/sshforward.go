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

// forwardSSH owns both authenticated connections. It forwards the connection
// protocol opaquely and returns only after all forwarding workers have stopped.
// Closing either transport, or cancelling ctx, closes both connections so even
// blocked channel opens, request replies and flow-controlled writes can finish.
func forwardSSH(ctx context.Context, downstream, upstream sshPeer) error {
	var workers sync.WaitGroup
	exited := make(chan error, 2)
	for _, peer := range []sshPeer{downstream, upstream} {
		workers.Go(func() { exited <- peer.conn.Wait() })
	}
	workers.Go(func() { forwardSSHChannels(upstream.conn, downstream.channels) })
	workers.Go(func() { forwardSSHChannels(downstream.conn, upstream.channels) })
	workers.Go(func() { forwardSSHRequests(upstream.conn, downstream.requests) })
	workers.Go(func() { forwardSSHRequests(downstream.conn, upstream.requests) })
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-exited:
	}
	_ = downstream.conn.Close()
	_ = upstream.conn.Close()
	workers.Wait()
	return err
}

func forwardSSHChannels(destination ssh.Conn, channels <-chan ssh.NewChannel) {
	var workers sync.WaitGroup
	for channel := range channels {
		workers.Go(func() { forwardSSHChannel(destination, channel) })
	}
	workers.Wait()
}

func forwardSSHChannel(destination ssh.Conn, incoming ssh.NewChannel) {
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
	local, localRequests, err := incoming.Accept()
	if err != nil {
		_ = remote.Close()
		// Even a failed accept must service the already-opened peer's requests.
		ssh.DiscardRequests(remoteRequests)
		return
	}
	var workers sync.WaitGroup
	workers.Go(func() { forwardSSHChannelDirection(local, remote, remoteRequests) })
	workers.Go(func() { forwardSSHChannelDirection(remote, local, localRequests) })
	workers.Wait()
}

// Each direction closes its destination only after its source has closed and
// both buffered data streams and requests have drained. In particular, EOF
// alone cannot close a channel: a command may still produce output and status
// after stdin EOF. Treat either endpoint's CLOSE symmetrically so a caller can
// close one channel without leaving its peer open for the connection's lifetime.
func forwardSSHChannelDirection(destination, source ssh.Channel, requests <-chan *ssh.Request) {
	var streams sync.WaitGroup
	streams.Go(func() { copySSHChannel(destination, source) })
	forwardSSHRequests(sshChannelRequestSender{destination}, requests)
	streams.Wait()
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

// Replies are positional, so each direction must forward requests serially.
// Keep draining after send errors: an unread request queue can block the entire
// SSH mux, including unrelated channels and transport shutdown.
func forwardSSHRequests(destination sshRequestSender, requests <-chan *ssh.Request) {
	for request := range requests {
		ok, payload, err := destination.SendRequest(request.Type, request.WantReply, request.Payload)
		if err != nil {
			ok, payload = false, nil
		}
		if request.WantReply {
			_ = request.Reply(ok, payload)
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
