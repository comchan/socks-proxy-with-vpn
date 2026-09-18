package tunnels

import (
	"context"
	"fmt"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
	sshbackend "github.com/comchan/socks-proxy-thru-wireguard/internal/tunnels/ssh"
)

// NewConnector maps a validated profile to its tunnel backend. M3 supports
// SSH; OpenVPN and WireGuard are intentionally explicit future errors.
func NewConnector(ctx context.Context, profile config.ProfileConfig) (egress.Connector, error) {
	switch strings.ToLower(strings.TrimSpace(profile.Backend)) {
	case "ssh":
		return sshbackend.New(ctx, profile)
	case "openvpn", "wireguard":
		return nil, fmt.Errorf("tunnel backend %q is not implemented yet", profile.Backend)
	default:
		return nil, fmt.Errorf("unknown tunnel backend %q", profile.Backend)
	}
}
