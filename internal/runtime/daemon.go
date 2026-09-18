package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/gateway"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/policy"
)

type ConnectorFactory func(context.Context, config.ProfileConfig) (egress.Connector, error)
type ListenFunc func(network, address string) (net.Listener, error)

type listenerRuntime struct {
	protocol     string
	gateway      *gateway.Gateway
	tlsConfig    *tls.Config
	sourceFilter *policy.SourceFilter
}

// Daemon owns listener and connection lifecycles. Tunnel adapters are supplied
// by a factory so M2 can be tested without privileged VPN access.
type Daemon struct {
	listenersSpec  []listenerRuntime
	listenerConfig []config.ListenerConfig
	listen         ListenFunc

	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	listeners   []net.Listener
	connections map[net.Conn]struct{}
	started     bool

	acceptWG        sync.WaitGroup
	connectionWG    sync.WaitGroup
	shutdownOnce    sync.Once
	shutdownDone    chan struct{}
	shutdownErr     error
	shutdownTimeout time.Duration
}

func New(cfg config.Config, factory ConnectorFactory) (*Daemon, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, errors.New("connector factory is required")
	}
	shutdownTimeout, err := cfg.GracefulShutdownTimeout()
	if err != nil {
		return nil, err
	}

	profileConnectors := make(map[string]egress.Connector, len(cfg.Profiles))
	for _, profile := range cfg.Profiles {
		connector, err := factory(context.Background(), profile)
		if err != nil {
			return nil, fmt.Errorf("create connector for profile %q: %w", profile.ID, err)
		}
		if connector == nil {
			return nil, fmt.Errorf("connector factory returned nil for profile %q", profile.ID)
		}
		profileConnectors[profile.ID] = connector
	}

	runtimes := make([]listenerRuntime, 0, len(cfg.Listeners))
	for _, listener := range cfg.Listeners {
		selector, err := policy.NewRouteSelector(listener.Profile, listener.Routes)
		if err != nil {
			return nil, fmt.Errorf("listener %q routes: %w", listener.ID, err)
		}
		routed, err := policy.NewRoutedConnector(selector, profileConnectors)
		if err != nil {
			return nil, fmt.Errorf("listener %q routing: %w", listener.ID, err)
		}
		auth, err := policy.NewAuthenticator(listener.Auth)
		if err != nil {
			return nil, fmt.Errorf("listener %q auth: %w", listener.ID, err)
		}
		acl, err := policy.NewACL(listener.ACL)
		if err != nil {
			return nil, fmt.Errorf("listener %q ACL: %w", listener.ID, err)
		}
		sourceFilter, err := policy.NewSourceFilter(listener.ACL.SourceCIDRs)
		if err != nil {
			return nil, fmt.Errorf("listener %q source filter: %w", listener.ID, err)
		}
		tlsConfig, err := buildTLSConfig(listener.TLS)
		if err != nil {
			return nil, fmt.Errorf("listener %q TLS: %w", listener.ID, err)
		}
		proxyGateway := gateway.New(routed)
		proxyGateway.Authenticator = auth
		proxyGateway.DestinationACL = acl
		runtimes = append(runtimes, listenerRuntime{
			protocol:     listener.Protocol,
			gateway:      proxyGateway,
			tlsConfig:    tlsConfig,
			sourceFilter: sourceFilter,
		})
	}

	return &Daemon{
		listenersSpec:   runtimes,
		listenerConfig:  cfg.Listeners,
		listen:          net.Listen,
		connections:     make(map[net.Conn]struct{}),
		shutdownDone:    make(chan struct{}),
		shutdownTimeout: shutdownTimeout,
	}, nil
}

func (d *Daemon) SetListenFunc(listen ListenFunc) {
	if listen != nil {
		d.listen = listen
	}
}

func (d *Daemon) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return errors.New("daemon is already started")
	}
	d.ctx, d.cancel = context.WithCancel(parent)
	d.started = true
	d.mu.Unlock()

	for index, listenerSpec := range d.listenerConfig {
		address := net.JoinHostPort(listenerSpec.Host, strconv.Itoa(int(listenerSpec.Port)))
		listener, err := d.listen("tcp", address)
		if err != nil {
			_ = d.Shutdown(context.Background())
			return fmt.Errorf("listen for listener %q: %w", listenerSpec.ID, err)
		}
		d.mu.Lock()
		d.listeners = append(d.listeners, listener)
		d.mu.Unlock()
		d.acceptWG.Add(1)
		go d.acceptLoop(d.listenersSpec[index], listener)
	}
	return nil
}

func (d *Daemon) Addresses() []net.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	addresses := make([]net.Addr, 0, len(d.listeners))
	for _, listener := range d.listeners {
		addresses = append(addresses, listener.Addr())
	}
	return addresses
}

func (d *Daemon) acceptLoop(spec listenerRuntime, listener net.Listener) {
	defer d.acceptWG.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if d.contextDone() {
				return
			}
			return
		}
		if !spec.sourceFilter.Allow(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}
		d.track(conn)
		d.connectionWG.Add(1)
		go d.serveConnection(spec, conn)
	}
}

func (d *Daemon) serveConnection(spec listenerRuntime, raw net.Conn) {
	defer d.connectionWG.Done()
	defer d.untrack(raw)
	defer func() { _ = raw.Close() }()

	conn := raw
	if spec.tlsConfig != nil {
		tlsConn := tls.Server(raw, spec.tlsConfig)
		if err := tlsConn.HandshakeContext(d.context()); err != nil {
			return
		}
		conn = tlsConn
		defer func() { _ = tlsConn.Close() }()
	}

	switch spec.protocol {
	case "http":
		_ = spec.gateway.ServeHTTP(d.context(), conn)
	case "socks4":
		_ = spec.gateway.ServeSOCKS4(d.context(), conn)
	case "socks5":
		_ = spec.gateway.ServeSOCKS5(d.context(), conn)
	default:
		_ = conn.Close()
	}
}

func (d *Daemon) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		timeout := d.shutdownTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	d.shutdownOnce.Do(func() {
		d.shutdownErr = d.shutdown(ctx)
		close(d.shutdownDone)
	})
	<-d.shutdownDone
	return d.shutdownErr
}

func (d *Daemon) shutdown(ctx context.Context) error {
	d.mu.Lock()
	if !d.started {
		d.mu.Unlock()
		return nil
	}
	cancel := d.cancel
	listeners := append([]net.Listener(nil), d.listeners...)
	d.mu.Unlock()

	cancel()
	for _, listener := range listeners {
		_ = listener.Close()
	}

	finished := make(chan struct{})
	go func() {
		d.acceptWG.Wait()
		d.connectionWG.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		d.closeConnections()
		<-finished
		return ctx.Err()
	}
}

func (d *Daemon) track(conn net.Conn) {
	d.mu.Lock()
	d.connections[conn] = struct{}{}
	d.mu.Unlock()
}

func (d *Daemon) untrack(conn net.Conn) {
	d.mu.Lock()
	delete(d.connections, conn)
	d.mu.Unlock()
}

func (d *Daemon) closeConnections() {
	d.mu.Lock()
	connections := make([]net.Conn, 0, len(d.connections))
	for conn := range d.connections {
		connections = append(connections, conn)
	}
	d.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (d *Daemon) context() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx == nil {
		return context.Background()
	}
	return d.ctx
}

func (d *Daemon) contextDone() bool {
	return d.context().Err() != nil
}

func buildTLSConfig(spec *config.TLSConfig) (*tls.Config, error) {
	if spec == nil || (spec.CertFile == "" && spec.KeyFile == "") {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(spec.CertFile, spec.KeyFile)
	if err != nil {
		return nil, err
	}
	result := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}
	if spec.ClientCAFile != "" {
		data, err := os.ReadFile(spec.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		appended := false
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type == "CERTIFICATE" && pool.AppendCertsFromPEM(pem.EncodeToMemory(block)) {
				appended = true
			}
		}
		if !appended {
			return nil, errors.New("clientCAFile contains no certificates")
		}
		result.ClientCAs = pool
		if spec.RequireClientCertificate {
			result.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			result.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return result, nil
}
