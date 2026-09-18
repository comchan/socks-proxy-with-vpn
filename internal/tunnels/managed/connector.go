package managed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	interfacebackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/interface"
)

const defaultStartupTimeout = 30 * time.Second

type Connector struct {
	attached  *interfacebackend.Connector
	lifecycle *Lifecycle
	closeOnce sync.Once
	closeErr  error
}

type Lifecycle struct {
	runner  Runner
	process *ProcessHandle
	stop    *Command
}

func New(ctx context.Context, profile config.ProfileConfig) (*Connector, error) {
	return NewWithRunner(ctx, profile, ExecRunner{})
}

func NewWithRunner(ctx context.Context, profile config.ProfileConfig, runner Runner) (*Connector, error) {
	if runner == nil {
		return nil, errors.New("managed VPN runner is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	plan, err := BuildPlan(profile)
	if err != nil {
		return nil, err
	}
	startupTimeout := defaultStartupTimeout
	if profile.StartupTimeout != "" {
		startupTimeout, err = time.ParseDuration(profile.StartupTimeout)
		if err != nil || startupTimeout <= 0 {
			return nil, errors.New("managed VPN startupTimeout must be positive")
		}
	}
	startupCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()

	lifecycle := &Lifecycle{runner: runner, stop: plan.Stop}
	if plan.OneShot {
		if err := runner.Run(startupCtx, plan.Start); err != nil {
			return nil, fmt.Errorf("start managed %s: %w", profile.Backend, err)
		}
	} else {
		process, err := StartProcess(startupCtx, runner, plan.Start)
		if err != nil {
			return nil, fmt.Errorf("start managed %s: %w", profile.Backend, err)
		}
		lifecycle.process = process
		if err := process.WaitForMarker(startupCtx, plan.ReadyMarker); err != nil {
			_ = lifecycle.Close(context.Background())
			return nil, fmt.Errorf("managed %s readiness: %w", profile.Backend, err)
		}
	}

	attachedProfile := profile
	attachedProfile.Mode = "attached-interface"
	var attached *interfacebackend.Connector
	var lastErr error
	for {
		attached, lastErr = interfacebackend.New(startupCtx, attachedProfile)
		if lastErr == nil {
			break
		}
		if startupCtx.Err() != nil {
			_ = lifecycle.Close(context.Background())
			return nil, fmt.Errorf("managed %s interface readiness: %w", profile.Backend, lastErr)
		}
		select {
		case <-startupCtx.Done():
			_ = lifecycle.Close(context.Background())
			return nil, fmt.Errorf("managed %s interface readiness: %w", profile.Backend, lastErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return &Connector{attached: attached, lifecycle: lifecycle}, nil
}

func (c *Connector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	if c == nil || c.attached == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("managed VPN connector is closed"))
	}
	return c.attached.OpenTCP(ctx, destination)
}

func (c *Connector) OpenUDP(ctx context.Context) (net.PacketConn, error) {
	if c == nil || c.attached == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("managed VPN connector is closed"))
	}
	return c.attached.OpenUDP(ctx)
}

func (c *Connector) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	if c == nil || c.attached == nil {
		return nil, egress.NewError(egress.FailureGeneral, errors.New("managed VPN connector is closed"))
	}
	return c.attached.Resolve(ctx, hostname)
}

func (c *Connector) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.attached != nil {
			_ = c.attached.Close()
		}
		if c.lifecycle != nil {
			closeContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			c.closeErr = c.lifecycle.Close(closeContext)
			cancel()
		}
	})
	return c.closeErr
}

func (l *Lifecycle) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var firstErr error
	if l.process != nil {
		if err := l.process.Stop(ctx); err != nil && !strings.Contains(err.Error(), "already finished") {
			firstErr = err
		}
	}
	if l.stop != nil {
		if err := l.runner.Run(ctx, *l.stop); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
