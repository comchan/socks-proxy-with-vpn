package managed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

type Command struct {
	Name string
	Args []string
}

func (c Command) Validate() error {
	if c.Name == "" {
		return errors.New("managed command name is required")
	}
	for _, arg := range append([]string{c.Name}, c.Args...) {
		if stringsContainsNUL(arg) {
			return errors.New("managed command contains a NUL byte")
		}
	}
	return nil
}

type Process interface {
	Stdout() io.ReadCloser
	Stderr() io.ReadCloser
	Wait() error
	Kill() error
}

type Runner interface {
	Start(context.Context, Command) (Process, error)
	Run(context.Context, Command) error
}

type ExecRunner struct{}

func (ExecRunner) Start(ctx context.Context, command Command) (Process, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create managed stdout pipe: %w", err)
	}
	stderr, err := process.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("create managed stderr pipe: %w", err)
	}
	if err := process.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start managed command %q: %w", command.Name, err)
	}
	return &execProcess{process: process, stdout: stdout, stderr: stderr}, nil
}

func (ExecRunner) Run(ctx context.Context, command Command) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := exec.CommandContext(ctx, command.Name, command.Args...).Run(); err != nil {
		return fmt.Errorf("run managed command %q: %w", command.Name, err)
	}
	return nil
}

type execProcess struct {
	process *exec.Cmd
	stdout  io.ReadCloser
	stderr  io.ReadCloser
}

func (p *execProcess) Stdout() io.ReadCloser { return p.stdout }
func (p *execProcess) Stderr() io.ReadCloser { return p.stderr }
func (p *execProcess) Wait() error           { return p.process.Wait() }
func (p *execProcess) Kill() error {
	if p.process.Process == nil {
		return os.ErrProcessDone
	}
	return p.process.Process.Kill()
}

func stringsContainsNUL(value string) bool {
	for _, character := range value {
		if character == 0 {
			return true
		}
	}
	return false
}
