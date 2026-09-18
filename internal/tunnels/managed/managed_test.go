package managed

import (
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/comchan/socks-proxy-thru-wireguard/internal/config"
)

type fakeProcess struct {
	stdoutReader *io.PipeReader
	stdoutWriter *io.PipeWriter
	stderrReader *io.PipeReader
	stderrWriter *io.PipeWriter
	done         chan struct{}
	killOnce     sync.Once
}

func newFakeProcess(marker string) *fakeProcess {
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	process := &fakeProcess{
		stdoutReader: stdoutReader,
		stdoutWriter: stdoutWriter,
		stderrReader: stderrReader,
		stderrWriter: stderrWriter,
		done:         make(chan struct{}),
	}
	if marker != "" {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _ = stdoutWriter.Write([]byte(marker + "\n"))
		}()
	}
	return process
}

func (p *fakeProcess) Stdout() io.ReadCloser { return p.stdoutReader }
func (p *fakeProcess) Stderr() io.ReadCloser { return p.stderrReader }
func (p *fakeProcess) Wait() error {
	<-p.done
	return nil
}
func (p *fakeProcess) Kill() error {
	p.killOnce.Do(func() {
		_ = p.stdoutWriter.Close()
		_ = p.stderrWriter.Close()
		close(p.done)
	})
	return nil
}

type fakeRunner struct {
	process    *fakeProcess
	startCalls []Command
	runCalls   []Command
	mu         sync.Mutex
}

func (r *fakeRunner) Start(_ context.Context, command Command) (Process, error) {
	r.mu.Lock()
	r.startCalls = append(r.startCalls, command)
	r.mu.Unlock()
	return r.process, nil
}

func (r *fakeRunner) Run(_ context.Context, command Command) error {
	r.mu.Lock()
	r.runCalls = append(r.runCalls, command)
	r.mu.Unlock()
	return nil
}

func managedProfile(backend string) config.ProfileConfig {
	return config.ProfileConfig{
		ID:             backend,
		Backend:        backend,
		Mode:           "managed-process",
		ConfigPath:     "/etc/vpnfront/test.conf",
		LocalAddress:   "127.0.0.1",
		StartupTimeout: "500ms",
	}
}

func TestBuildPlanOpenVPNUsesExplicitArguments(t *testing.T) {
	profile := managedProfile("openvpn")
	profile.ClientPath = "/usr/local/sbin/openvpn"
	plan, err := BuildPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Start.Name != profile.ClientPath || len(plan.Start.Args) != 2 || plan.Start.Args[0] != "--config" || plan.Start.Args[1] != profile.ConfigPath {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.ReadyMarker == "" || plan.OneShot {
		t.Fatalf("OpenVPN plan = %+v", plan)
	}
}

func TestBuildPlanWireGuardUsesPlatformLifecycle(t *testing.T) {
	plan, err := BuildPlan(managedProfile("wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.OneShot || plan.Stop == nil {
		t.Fatalf("WireGuard plan = %+v", plan)
	}
	if runtime.GOOS == "windows" {
		if plan.Start.Args[0] != "/installtunnelservice" || plan.Stop.Args[0] != "/uninstalltunnelservice" {
			t.Fatalf("Windows WireGuard plan = %+v", plan)
		}
	} else if plan.Start.Args[0] != "up" || plan.Stop.Args[0] != "down" {
		t.Fatalf("Unix WireGuard plan = %+v", plan)
	}
}

func TestManagedOpenVPNWaitsForReadinessAndStopsProcess(t *testing.T) {
	process := newFakeProcess("Initialization Sequence Completed")
	runner := &fakeRunner{process: process}
	connector, err := NewWithRunner(context.Background(), managedProfile("openvpn"), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.startCalls) != 1 || runner.startCalls[0].Args[0] != "--config" {
		t.Fatalf("start calls = %+v", runner.startCalls)
	}
	if err := connector.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("managed process was not stopped")
	}
}

func TestManagedWireGuardRunsUpAndDown(t *testing.T) {
	runner := &fakeRunner{}
	connector, err := NewWithRunner(context.Background(), managedProfile("wireguard"), runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.runCalls) != 1 || runner.runCalls[0].Args[0] != "up" {
		t.Fatalf("start commands = %+v", runner.runCalls)
	}
	if err := connector.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runner.runCalls) != 2 || runner.runCalls[1].Args[0] != "down" {
		t.Fatalf("lifecycle commands = %+v", runner.runCalls)
	}
}

func TestManagedOpenVPNTimesOutBeforeReadiness(t *testing.T) {
	profile := managedProfile("openvpn")
	profile.StartupTimeout = "20ms"
	process := newFakeProcess("")
	runner := &fakeRunner{process: process}
	_, err := NewWithRunner(context.Background(), profile, runner)
	if err == nil || !strings.Contains(err.Error(), "readiness") {
		t.Fatalf("error = %v, want readiness timeout", err)
	}
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("timed-out process was not stopped")
	}
}

func TestManagedVPNFailsWhenAttachedInterfaceCannotBecomeReady(t *testing.T) {
	profile := managedProfile("wireguard")
	profile.LocalAddress = ""
	profile.Interface = "vpnfront-missing-interface"
	profile.StartupTimeout = "20ms"
	process := newFakeProcess("")
	runner := &fakeRunner{process: process}
	_, err := NewWithRunner(context.Background(), profile, runner)
	if err == nil || !strings.Contains(err.Error(), "interface readiness") {
		t.Fatalf("error = %v, want interface-readiness failure", err)
	}
	select {
	case <-process.done:
	default:
		// WireGuard is one-shot; the cleanup command is the lifecycle assertion.
		if len(runner.runCalls) < 2 {
			t.Fatal("failed interface startup did not run cleanup")
		}
	}
}

func TestCommandRejectsNULBytes(t *testing.T) {
	if err := (Command{Name: "openvpn", Args: []string{"--config", "bad\x00path"}}).Validate(); err == nil {
		t.Fatal("NUL-containing command should be rejected")
	}
}
