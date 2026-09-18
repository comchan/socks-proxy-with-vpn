//go:build linux && integration

package interfacebackend

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
)

func TestLinuxAttachedInterfaceDoesNotFallbackWhenInterfaceMissing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires privileged Linux runner")
	}
	_, err := New(context.Background(), config.ProfileConfig{
		Backend:   "wireguard",
		Mode:      "attached-interface",
		Interface: "vpnfront-missing-interface",
	})
	if !errors.Is(err, ErrInterfaceUnavailable) {
		t.Fatalf("error = %v, want fail-closed interface error", err)
	}
}
