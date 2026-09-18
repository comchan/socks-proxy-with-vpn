package domain

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Destination is an unresolved host and port requested by a proxy client.
// Hostnames remain unresolved until the selected egress profile handles them.
type Destination struct {
	Host string
	Port uint16
}

func (d Destination) String() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

func (d Destination) Valid() bool {
	return strings.TrimSpace(d.Host) != "" && d.Port != 0
}

// ParseAddress parses an address that must contain a non-zero port.
func ParseAddress(address string) (Destination, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return Destination{}, fmt.Errorf("parse destination %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return Destination{}, fmt.Errorf("invalid destination port %q", portText)
	}
	if strings.TrimSpace(host) == "" {
		return Destination{}, fmt.Errorf("destination host is empty")
	}
	return Destination{Host: host, Port: uint16(port)}, nil
}

// ParseHostPort parses a host with an optional port, applying defaultPort when
// the input is a bare hostname or IPv4 address.
func ParseHostPort(address string, defaultPort uint16) (Destination, error) {
	if strings.TrimSpace(address) == "" {
		return Destination{}, fmt.Errorf("destination is empty")
	}
	if host, portText, err := net.SplitHostPort(address); err == nil {
		port, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || port == 0 {
			return Destination{}, fmt.Errorf("invalid destination port %q", portText)
		}
		if strings.TrimSpace(host) == "" {
			return Destination{}, fmt.Errorf("destination host is empty")
		}
		return Destination{Host: host, Port: uint16(port)}, nil
	}
	if len(address) >= 2 && address[0] == '[' && address[len(address)-1] == ']' {
		if defaultPort == 0 {
			return Destination{}, fmt.Errorf("default destination port is zero")
		}
		return Destination{Host: address[1 : len(address)-1], Port: defaultPort}, nil
	}
	if strings.Contains(address, ":") {
		return Destination{}, fmt.Errorf("destination %q must include a port for an IPv6 address", address)
	}
	if defaultPort == 0 {
		return Destination{}, fmt.Errorf("default destination port is zero")
	}
	return Destination{Host: address, Port: defaultPort}, nil
}
