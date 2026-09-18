package policy

import (
	"errors"
	"net"
	"strings"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

var ErrDenied = errors.New("destination denied by policy")

// ACL evaluates destination rules in deny, allow, then default order. The
// metadata endpoint and IPv6 link-local range are denied regardless of config.
type ACL struct {
	defaultAllow bool
	allowCIDRs   []*net.IPNet
	denyCIDRs    []*net.IPNet
	allowDomains []string
	denyDomains  []string
}

func NewACL(spec config.ACLConfig) (*ACL, error) {
	acl := &ACL{defaultAllow: spec.DefaultAction == "allow"}
	var err error
	if acl.allowCIDRs, err = parseCIDRs(spec.AllowCIDRs); err != nil {
		return nil, err
	}
	if acl.denyCIDRs, err = parseCIDRs(append([]string{"169.254.169.254/32", "fe80::/10"}, spec.DenyCIDRs...)); err != nil {
		return nil, err
	}
	acl.allowDomains = normalizeDomains(spec.AllowDomains)
	acl.denyDomains = normalizeDomains(spec.DenyDomains)
	return acl, nil
}

func (a *ACL) Allow(destination domain.Destination) error {
	if a == nil {
		return nil
	}
	if ip := net.ParseIP(destination.Host); ip != nil {
		if containsIP(a.denyCIDRs, ip) || (!containsIP(a.allowCIDRs, ip) && !a.defaultAllow) {
			return ErrDenied
		}
		if len(a.allowCIDRs) > 0 && !containsIP(a.allowCIDRs, ip) {
			return ErrDenied
		}
		return nil
	}
	host := normalizeDomain(destination.Host)
	if matchesDomain(a.denyDomains, host) || (!matchesDomain(a.allowDomains, host) && !a.defaultAllow) {
		return ErrDenied
	}
	if len(a.allowDomains) > 0 && !matchesDomain(a.allowDomains, host) {
		return ErrDenied
	}
	return nil
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		result = append(result, network)
	}
	return result, nil
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeDomain(value); normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	value = strings.TrimPrefix(value, "*.")
	return strings.TrimPrefix(value, ".")
}

func matchesDomain(suffixes []string, host string) bool {
	for _, suffix := range suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
