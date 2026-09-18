package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
)

var ErrNoRoute = errors.New("no egress route matches destination")

type routeRule struct {
	cidr         *net.IPNet
	domainSuffix string
	profile      string
	isDefault    bool
}

type RouteSelector struct {
	defaultProfile string
	rules          []routeRule
}

func NewRouteSelector(defaultProfile string, routes []config.RouteConfig) (*RouteSelector, error) {
	selector := &RouteSelector{defaultProfile: defaultProfile}
	for _, route := range routes {
		rule := routeRule{profile: route.Profile, isDefault: route.Default}
		if route.CIDR != "" {
			_, network, err := net.ParseCIDR(route.CIDR)
			if err != nil {
				return nil, fmt.Errorf("parse route CIDR %q: %w", route.CIDR, err)
			}
			rule.cidr = network
		}
		if route.DomainSuffix != "" {
			rule.domainSuffix = normalizeDomain(route.DomainSuffix)
		}
		selector.rules = append(selector.rules, rule)
		if route.Default {
			selector.defaultProfile = route.Profile
		}
	}
	return selector, nil
}

func (s *RouteSelector) Select(destination domain.Destination) (string, error) {
	if s == nil {
		return "", ErrNoRoute
	}
	ip := net.ParseIP(destination.Host)
	host := normalizeDomain(destination.Host)
	for _, rule := range s.rules {
		if rule.cidr != nil && ip != nil && rule.cidr.Contains(ip) {
			return rule.profile, nil
		}
		if rule.domainSuffix != "" && (host == rule.domainSuffix || strings.HasSuffix(host, "."+rule.domainSuffix)) {
			return rule.profile, nil
		}
		if rule.isDefault {
			return rule.profile, nil
		}
	}
	if s.defaultProfile == "" {
		return "", ErrNoRoute
	}
	return s.defaultProfile, nil
}

// RoutedConnector selects a profile for each TCP destination. UDP uses the
// listener/default profile because the SOCKS5 UDP association opens its packet
// socket before individual datagram targets arrive.
type RoutedConnector struct {
	selector *RouteSelector
	profiles map[string]egress.Connector
}

func NewRoutedConnector(selector *RouteSelector, profiles map[string]egress.Connector) (*RoutedConnector, error) {
	if selector == nil {
		return nil, errors.New("route selector is required")
	}
	if len(profiles) == 0 {
		return nil, errors.New("at least one egress profile is required")
	}
	return &RoutedConnector{selector: selector, profiles: profiles}, nil
}

func (r *RoutedConnector) OpenTCP(ctx context.Context, destination domain.Destination) (net.Conn, error) {
	profile, err := r.Select(destination)
	if err != nil {
		return nil, err
	}
	return profile.OpenTCP(ctx, destination)
}

func (r *RoutedConnector) OpenUDP(ctx context.Context) (net.PacketConn, error) {
	profile, err := r.Select(domain.Destination{Host: "0.0.0.0", Port: 1})
	if err != nil {
		return nil, err
	}
	return profile.OpenUDP(ctx)
}

func (r *RoutedConnector) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	profile, err := r.Select(domain.Destination{Host: hostname, Port: 53})
	if err != nil {
		return nil, err
	}
	return profile.Resolve(ctx, hostname)
}

func (r *RoutedConnector) Select(destination domain.Destination) (egress.Connector, error) {
	profileID, err := r.selector.Select(destination)
	if err != nil {
		return nil, err
	}
	profile, ok := r.profiles[profileID]
	if !ok {
		return nil, fmt.Errorf("route selects unknown profile %q", profileID)
	}
	return profile, nil
}
