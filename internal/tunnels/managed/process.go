package managed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type ProcessHandle struct {
	process Process
	done    chan struct{}
	lines   chan string
	mu      sync.RWMutex
	waitErr error
}

func StartProcess(ctx context.Context, runner Runner, command Command) (*ProcessHandle, error) {
	process, err := runner.Start(ctx, command)
	if err != nil {
		return nil, err
	}
	handle := &ProcessHandle{
		process: process,
		done:    make(chan struct{}),
		lines:   make(chan string, 32),
	}
	go func() {
		err := process.Wait()
		handle.mu.Lock()
		handle.waitErr = err
		handle.mu.Unlock()
		close(handle.done)
	}()
	go scanLines(process.Stdout(), handle.lines)
	go scanLines(process.Stderr(), handle.lines)
	return handle, nil
}

func (h *ProcessHandle) Wait() <-chan struct{} { return h.done }

func (h *ProcessHandle) Error() error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.waitErr
}

func (h *ProcessHandle) WaitForMarker(ctx context.Context, marker string) error {
	if strings.TrimSpace(marker) == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.done:
			err := h.Error()
			if err == nil {
				return errors.New("managed process exited before readiness")
			}
			return fmt.Errorf("managed process exited before readiness: %w", err)
		case line, ok := <-h.lines:
			if !ok {
				return errors.New("managed process output closed before readiness")
			}
			if strings.Contains(line, marker) {
				return nil
			}
		}
	}
}

func (h *ProcessHandle) Stop(ctx context.Context) error {
	if h == nil || h.process == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	killErr := h.process.Kill()
	select {
	case <-h.done:
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return killErr
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func scanLines(reader io.Reader, lines chan<- string) {
	if reader == nil {
		return
	}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		lines <- scanner.Text()
	}
}
