package policy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

type routeTestConnector struct{}

func (routeTestConnector) OpenTCP(context.Context, domain.Destination) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (routeTestConnector) OpenUDP(context.Context) (net.PacketConn, error) {
	return nil, errors.New("not used")
}
func (routeTestConnector) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("not used")
}

func TestRouteSelectorUsesOrderedRules(t *testing.T) {
	selector, err := NewRouteSelector("public", []config.RouteConfig{
		{CIDR: "10.0.0.0/8", Profile: "corp"},
		{DomainSuffix: ".internal.example", Profile: "private"},
		{Default: true, Profile: "public"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		destination domain.Destination
		want        string
	}{
		{name: "CIDR", destination: domain.Destination{Host: "10.1.2.3", Port: 443}, want: "corp"},
		{name: "domain", destination: domain.Destination{Host: "api.internal.example", Port: 443}, want: "private"},
		{name: "default", destination: domain.Destination{Host: "example.com", Port: 443}, want: "public"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got, err := selector.Select(test.destination); err != nil || got != test.want {
				t.Fatalf("Select() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestRoutedConnectorRejectsMissingDefault(t *testing.T) {
	selector, err := NewRouteSelector("", nil)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := NewRoutedConnector(selector, map[string]egress.Connector{"test": routeTestConnector{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.OpenTCP(context.Background(), domain.Destination{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("missing route should be rejected")
	}
}
