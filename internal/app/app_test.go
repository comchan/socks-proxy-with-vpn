package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if got := Run(context.Background(), []string{"--version"}, &stdout, &stderr); got != 0 {
		t.Fatalf("Run() exit code = %d, want 0", got)
	}
	if got, want := stdout.String(), "vpnfront dev\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunHelpIsDeterministic(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if got := Run(context.Background(), nil, &stdout, &stderr); got != 0 {
		t.Fatalf("Run() exit code = %d, want 0", got)
	}
	for _, expected := range []string{"vpnfront is a VPN-fronted", "-version", "The proxy listeners"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("stderr = %q, want substring %q", stderr.String(), expected)
		}
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if got := Run(context.Background(), []string{"unexpected"}, &stdout, &stderr); got != 2 {
		t.Fatalf("Run() exit code = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "unexpected arguments") {
		t.Fatalf("stderr = %q, want argument error", stderr.String())
	}
}

func TestRunHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer

	if got := Run(ctx, nil, &stdout, &stderr); got != 1 {
		t.Fatalf("Run() exit code = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("stderr = %q, want context cancellation", stderr.String())
	}
}
