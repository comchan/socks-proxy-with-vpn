package gateway

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRelayCopiesBothDirections(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Relay(context.Background(), left, right) }()
	defer func() {
		_ = left.Close()
		_ = leftPeer.Close()
		_ = right.Close()
		_ = rightPeer.Close()
	}()

	go func() { _, _ = leftPeer.Write([]byte("left-to-right")) }()
	data := readN(t, rightPeer, len("left-to-right"))
	if string(data) != "left-to-right" {
		t.Fatalf("right received %q", data)
	}
	go func() { _, _ = rightPeer.Write([]byte("right-to-left")) }()
	data = readN(t, leftPeer, len("right-to-left"))
	if string(data) != "right-to-left" {
		t.Fatalf("left received %q", data)
	}
	_ = leftPeer.Close()
	_ = rightPeer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after both peers closed")
	}
}

func TestRelayStopsOnContextCancellation(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Relay(ctx, left, right) }()
	cancel()
	defer func() {
		_ = left.Close()
		_ = leftPeer.Close()
		_ = right.Close()
		_ = rightPeer.Close()
	}()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("relay error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after context cancellation")
	}
}
