package egress

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
)

// Connector is the only egress capability required by the proxy gateway.
// Implementations may use SSH channels, VPN-bound sockets, or a test adapter.
type Connector interface {
	OpenTCP(context.Context, domain.Destination) (net.Conn, error)
	OpenUDP(context.Context) (net.PacketConn, error)
	Resolve(context.Context, string) ([]net.IP, error)
}

type FailureKind uint8

const (
	FailureGeneral FailureKind = iota
	FailureNetworkUnreachable
	FailureHostUnreachable
	FailureConnectionRefused
	FailureTTLExpired
	FailureCommandNotSupported
	FailureAddressTypeNotSupported
)

// Error preserves a backend failure category for protocol-specific replies.
type Error struct {
	Kind FailureKind
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return failureKindName(e.Kind)
	}
	return fmt.Sprintf("%s: %v", failureKindName(e.Kind), e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func NewError(kind FailureKind, err error) error {
	return &Error{Kind: kind, Err: err}
}

func KindOf(err error) FailureKind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return FailureHostUnreachable
	}
	return FailureGeneral
}

func failureKindName(kind FailureKind) string {
	switch kind {
	case FailureNetworkUnreachable:
		return "network unreachable"
	case FailureHostUnreachable:
		return "host unreachable"
	case FailureConnectionRefused:
		return "connection refused"
	case FailureTTLExpired:
		return "TTL expired"
	case FailureCommandNotSupported:
		return "command not supported"
	case FailureAddressTypeNotSupported:
		return "address type not supported"
	default:
		return "general egress failure"
	}
}
