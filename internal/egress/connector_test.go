package egress

import (
	"errors"
	"net"
	"testing"
)

func TestKindOfRecognizesWrappedErrors(t *testing.T) {
	err := errors.New("refused")
	wrapped := errors.Join(NewError(FailureConnectionRefused, err), errors.New("context"))
	if got := KindOf(wrapped); got != FailureConnectionRefused {
		t.Fatalf("KindOf() = %v, want connection refused", got)
	}
}

func TestKindOfRecognizesTimeout(t *testing.T) {
	err := &net.DNSError{Err: "timeout", IsTimeout: true}
	if got := KindOf(err); got != FailureHostUnreachable {
		t.Fatalf("KindOf() = %v, want host unreachable", got)
	}
}
