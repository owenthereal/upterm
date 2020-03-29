package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/utils"
	"github.com/jingweno/upterm/ws"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	tcpDialTimeout = 1 * time.Second
)

type Opt struct {
	SSHAddr    string
	WSAddr     string
	NodeAddr   string
	KeyFiles   []string
	Network    string
	NetworkOpt []string
	MetricAddr string
}

func Start(opt Opt) error {
	network := networks.Get(opt.Network)
	if network == nil {
		return fmt.Errorf("unsupport network provider %q", opt.Network)
	}

	opts := parseNetworkOpt(opt.NetworkOpt)
	if err := network.SetOpts(opts); err != nil {
		return fmt.Errorf("network provider option error: %s", err)
	}

	signers, err := utils.CreateSignersFromFiles(opt.KeyFiles)
	if err != nil {
		return err
	}

	if pp := os.Getenv("PRIVATE_KEY"); pp != "" {
		ss, err := utils.CreateSigners([][]byte{[]byte(pp)})
		if err != nil {
			return err
		}

		signers = append(signers, ss...)
	}

	logger := log.New().WithField("app", "uptermd")

	// fallback node addr to ssh addr or ws addr if empty
	nodeAddr := opt.NodeAddr
	if nodeAddr == "" {
		nodeAddr = opt.SSHAddr
	}
	if nodeAddr == "" {
		nodeAddr = opt.WSAddr
	}

	var (
		sshln net.Listener
		wsln  net.Listener
	)

	if opt.SSHAddr != "" {
		sshln, err = net.Listen("tcp", opt.SSHAddr)
		if err != nil {
			return err
		}
	}

	if opt.WSAddr != "" {
		wsln, err = net.Listen("tcp", opt.WSAddr)
		if err != nil {
			return err
		}
	}

	var g run.Group
	{
		var mp provider.Provider
		if opt.MetricAddr == "" {
			mp = provider.NewDiscardProvider()
		} else {
			mp = provider.NewPrometheusProvider("upterm", "uptermd")
		}

		s := &Server{
			NodeAddr:        nodeAddr,
			HostSigners:     signers,
			NetworkProvider: network,
			Logger:          logger.WithField("component", "server"),
			MetricsProvider: mp,
		}
		g.Add(func() error {
			return s.ServeWithContext(context.Background(), sshln, wsln)
		}, func(err error) {
			s.Shutdown()
		})
	}
	{
		if opt.MetricAddr != "" {
			m := &MetricsServer{}
			g.Add(func() error {
				return m.ListenAndServe(opt.MetricAddr)
			}, func(err error) {
				_ = m.Shutdown(context.Background())
			})
		}
	}

	return g.Run()
}

func parseNetworkOpt(opts []string) NetworkOptions {
	result := make(NetworkOptions)
	for _, opt := range opts {
		split := strings.SplitN(opt, "=", 2)
		result[split[0]] = split[1]
	}

	return result
}

type Server struct {
	NodeAddr        string
	HostSigners     []ssh.Signer
	NetworkProvider NetworkProvider
	MetricsProvider provider.Provider
	Logger          log.FieldLogger

	sshln net.Listener
	wsln  net.Listener

	mux    sync.Mutex
	ctx    context.Context
	cancel func()
}

func (s *Server) Shutdown() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.sshln != nil {
		s.sshln.Close()
	}

	if s.wsln != nil {
		s.wsln.Close()
	}
}

func (s *Server) ServeWithContext(ctx context.Context, sshln net.Listener, wsln net.Listener) error {
	s.mux.Lock()
	s.sshln, s.wsln = sshln, wsln
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mux.Unlock()

	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()

	var g run.Group
	{
		g.Add(func() error {
			<-s.ctx.Done()
			return s.ctx.Err()
		}, func(err error) {
			s.cancel()
		})
	}
	{
		if sshln != nil {
			cd := connDialer{
				NodeAddr:            s.NodeAddr,
				SSHDDialListener:    sshdDialListener,
				SessionDialListener: sessionDialListener,
				NeighbourDialer:     tcpConnDialer{},
				Logger:              s.Logger.WithField("compoent", "ssh-conn-dialer"),
			}
			sshProxy := &SSHProxy{
				HostSigners:     s.HostSigners,
				ConnDialer:      cd,
				Logger:          s.Logger.WithField("componet", "ssh-proxy"),
				MetricsProvider: s.MetricsProvider,
			}
			g.Add(func() error {
				return sshProxy.Serve(sshln)
			}, func(err error) {
				_ = sshProxy.Shutdown()
			})
		}
	}
	{
		if wsln != nil {
			var cd ConnDialer
			if sshln == nil {
				cd = connDialer{
					NodeAddr:            s.NodeAddr,
					SSHDDialListener:    sshdDialListener,
					SessionDialListener: sessionDialListener,
					NeighbourDialer:     wsConnDialer{},
					Logger:              s.Logger.WithField("compoent", "ws-conn-dialer"),
				}
			} else {
				// If sshln is not nil, always dial to SSHProxy.
				// So Host/Client -> WSProxy -> SSHProxy -> SSHD/Session
				// This makes sure that SSHProxy terminates all SSH requests
				// which provides a consistent authentication machanism.
				cd = sshProxyDialer{
					sshProxyAddr: sshln.Addr().String(),
					Logger:       s.Logger.WithField("compoent", "ws-sshproxy-dialer"),
				}
			}
			ws := &WebSocketProxy{
				ConnDialer: cd,
				Logger:     s.Logger.WithField("componet", "ws-proxy"),
			}
			g.Add(func() error {
				return ws.Serve(wsln)
			}, func(err error) {
				_ = ws.Shutdown()
			})
		}
	}
	{
		ln, err := sshdDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := SSHD{
			HostSigners:         s.HostSigners, // TODO: use different host keys
			NodeAddr:            s.NodeAddr,
			SessionDialListener: sessionDialListener,
			Logger:              s.Logger.WithField("componet", "sshd"),
		}
		g.Add(func() error {
			return sshd.Serve(ln)
		}, func(err error) {
			_ = sshd.Shutdown()
		})
	}

	return g.Run()
}

type ConnDialer interface {
	Dial(id api.Identifier) (net.Conn, error)
}

type sshProxyDialer struct {
	sshProxyAddr string
	Logger       log.FieldLogger
}

func (d sshProxyDialer) Dial(id api.Identifier) (net.Conn, error) {
	// If it's a host request, dial to SSHProxy in the same node.
	// Otherwise, dial to the specified SSHProxy.
	if id.Type == api.Identifier_HOST {
		d.Logger.WithFields(log.Fields{"host": id.Id, "sshproxy-addr": d.sshProxyAddr}).Info("dialing sshproxy sshd")
		return net.DialTimeout("tcp", d.sshProxyAddr, tcpDialTimeout)
	}

	d.Logger.WithFields(log.Fields{"session": id.Id, "sshproxy-addr": d.sshProxyAddr, "addr": id.NodeAddr}).Info("dialing sshproxy session")
	return net.DialTimeout("tcp", id.NodeAddr, tcpDialTimeout)
}

type tcpConnDialer struct {
}

func (d tcpConnDialer) Dial(id api.Identifier) (net.Conn, error) {
	return net.DialTimeout("tcp", id.NodeAddr, tcpDialTimeout)
}

type wsConnDialer struct {
}

func (d wsConnDialer) Dial(id api.Identifier) (net.Conn, error) {
	u, err := url.Parse("ws://" + id.NodeAddr)
	if err != nil {
		return nil, err
	}
	encodedNodeAddr := base64.StdEncoding.EncodeToString([]byte(id.NodeAddr))
	u.User = url.UserPassword(id.Id, encodedNodeAddr)

	return ws.NewWSConn(u, true)
}

type connDialer struct {
	NodeAddr            string
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	NeighbourDialer     ConnDialer
	Logger              log.FieldLogger
}

func (cd connDialer) Dial(id api.Identifier) (net.Conn, error) {
	if id.Type == api.Identifier_HOST {
		cd.Logger.WithFields(log.Fields{"host": id.Id, "ndoe": cd.NodeAddr}).Info("dialing sshd")
		return cd.SSHDDialListener.Dial()
	} else {
		host, port, ee := net.SplitHostPort(id.NodeAddr)
		if ee != nil {
			return nil, fmt.Errorf("host address %s is malformed: %w", id.NodeAddr, ee)
		}
		addr := net.JoinHostPort(host, port)

		// if current node is matching, dial to session.
		// Otherwise, dial to neighbour node
		if cd.NodeAddr == addr {
			cd.Logger.WithFields(log.Fields{"session": id.Id, "node": cd.NodeAddr, "addr": addr}).Info("dialing session")
			return cd.SessionDialListener.Dial(id.Id)
		}

		cd.Logger.WithFields(log.Fields{"session": id.Id, "node": cd.NodeAddr, "addr": addr}).Info("dialing neighbour")
		return cd.NeighbourDialer.Dial(id)
	}
}
