package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/domain"
	"github.com/comchan/socks-proxy-thru-wireguard/internal/egress"
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

func TestRunValidatesConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	data := []byte("listeners:\n  - id: local\n    protocol: socks5\n    profile: test\nprofiles:\n  - id: test\n    backend: fake\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), []string{"--validate-config", path}, &stdout, &stderr); got != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%q", got, stderr.String())
	}
	if got, want := stdout.String(), "configuration valid\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	data := []byte("listeners: []\nprofiles: []\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), []string{"--validate-config", path}, &stdout, &stderr); got != 2 {
		t.Fatalf("Run() exit code = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "invalid configuration") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func TestRunStartRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), []string{"start"}, &stdout, &stderr); got != 2 {
		t.Fatalf("Run() exit code = %d, want 2", got)
	}
	if got, want := stderr.String(), "start requires --config <path>\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunStartStartsAndStopsDaemon(t *testing.T) {
	port := freeTCPPort(t)
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	data := []byte(fmt.Sprintf(`shutdownTimeout: 1s
listeners:
  - id: local
    protocol: socks5
    host: 127.0.0.1
    port: %d
    profile: test
profiles:
  - id: test
    backend: fake
`, port))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newReadinessWriter()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	factory := func(context.Context, config.ProfileConfig) (egress.Connector, error) {
		return startTestConnector{}, nil
	}
	go func() {
		done <- runStart(ctx, []string{"--config", path}, stdout, &stderr, factory)
	}()

	select {
	case <-stdout.ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("start did not report readiness; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("dial started listener: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close listener test connection: %v", err)
	}
	cancel()

	select {
	case got := <-done:
		if got != 0 {
			t.Fatalf("runStart() exit code = %d, stderr=%q", got, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start did not stop after context cancellation")
	}
	if !strings.Contains(stdout.String(), "listener id=local protocol=socks5") {
		t.Fatalf("stdout = %q, want listener status", stdout.String())
	}
}

type startTestConnector struct{}

func (startTestConnector) OpenTCP(context.Context, domain.Destination) (net.Conn, error) {
	return nil, fmt.Errorf("test connector does not open TCP")
}

func (startTestConnector) OpenUDP(context.Context) (net.PacketConn, error) {
	return nil, fmt.Errorf("test connector does not open UDP")
}

func (startTestConnector) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, fmt.Errorf("test connector does not resolve DNS")
}

type readinessWriter struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func newReadinessWriter() *readinessWriter {
	return &readinessWriter{ready: make(chan struct{})}
}

func (w *readinessWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written, err := w.data.Write(data)
	if bytes.Contains(w.data.Bytes(), []byte("vpnfront started")) {
		w.once.Do(func() { close(w.ready) })
	}
	return written, err
}

func (w *readinessWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release test port: %v", err)
	}
	return port
}
