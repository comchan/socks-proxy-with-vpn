package sshbackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var ErrUDPUnsupported = errors.New("standard SSH direct-tcpip does not support UDP")
var ErrRemoteResolutionUnsupported = errors.New("SSH connector requires a configured remote DNS relay")

const defaultSSHPort = 22

// Connector opens proxy egress streams through one authenticated SSH client.
// The SSH server performs hostname resolution for direct-tcpip destinations.
type Connector struct {
	client    *ssh.Client
	closeOnce sync.Once
}

func New(ctx context.Context, profile config.ProfileConfig) (*Connector, error) {
	if strings.TrimSpace(profile.Host) == "" {
		return nil, errors.New("SSH profile host is required")
	}
	if strings.TrimSpace(profile.User) == "" {
		return nil, errors.New("SSH profile user is required")
	}
	if strings.TrimSpace(profile.PrivateKeyPath) == "" {
		return nil, errors.New("SSH profile privateKeyPath is required")
	}
	if strings.TrimSpace(profile.KnownHostsPath) == "" {
		return nil, errors.New("SSH profile knownHostsPath is required; host-key verification cannot be disabled")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	keyData, err := os.ReadFile(profile.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH private key: %w", err)
	}
	hostKeyCallback, err := knownhosts.New(profile.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load SSH known_hosts: %w", err)
	}

	port := profile.Port
	if port == 0 {
		port = defaultSSHPort
	}
	address := net.JoinHostPort(profile.Host, strconv.Itoa(int(port)))
	clientConfig := &ssh.ClientConfig{
		User:            profile.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH server %s: %w", address, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, address, clientConfig)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("authenticate SSH server %s: %w", address, err)
	}
	_ = raw.SetDeadline(time.Time{})
	return &Connector{client: ssh.NewClient(conn, channels, requests)}, nil
}

func (c *Connector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if c == nil || c.client == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("SSH connector is closed"))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !destination.Valid() {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("SSH destination is invalid"))
	}
	connection, err := c.client.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		return nil, classifySSHError(err)
	}
	return connection, nil
}

func (c *Connector) OpenUDP(context.Context) (net.PacketConn, error) {
	return nil, egress.NewError(egress.FailureCommandNotSupported, ErrUDPUnsupported)
}

func (c *Connector) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, egress.NewError(egress.FailureCommandNotSupported, ErrRemoteResolutionUnsupported)
}

func (c *Connector) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() { err = c.client.Close() })
	return err
}

func classifySSHError(err error) error {
	if err == nil {
		return nil
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return egress.NewError(egress.FailureHostUnreachable, err)
	}
	return egress.NewError(egress.FailureGeneral, err)
}
