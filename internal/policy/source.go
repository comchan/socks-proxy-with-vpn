package policy

import "net"

type SourceFilter struct {
	networks []*net.IPNet
}

func NewSourceFilter(cidrs []string) (*SourceFilter, error) {
	networks, err := parseCIDRs(cidrs)
	if err != nil {
		return nil, err
	}
	return &SourceFilter{networks: networks}, nil
}

func (f *SourceFilter) Allow(address net.Addr) bool {
	if f == nil || len(f.networks) == 0 {
		return true
	}
	var ip net.IP
	switch value := address.(type) {
	case *net.TCPAddr:
		ip = value.IP
	case *net.UDPAddr:
		ip = value.IP
	}
	if ip == nil {
		return false
	}
	return containsIP(f.networks, ip)
}
