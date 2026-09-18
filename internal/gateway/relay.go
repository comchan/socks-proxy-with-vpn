package gateway

import (
	"context"
	"errors"
	"io"
)

type readWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

type closeWriter interface {
	CloseWrite() error
}

type relayResult struct {
	err error
}

// Relay copies bytes in both directions until both sides finish or ctx is
// canceled. A completed half is closed for writing when the source reaches
// EOF, allowing protocols that depend on half-close semantics to finish.
func Relay(ctx context.Context, left, right readWriteCloser) error {
	results := make(chan relayResult, 2)
	go relayOne(right, left, results)
	go relayOne(left, right, results)

	var firstErr error
	for completed := 0; completed < 2; completed++ {
		select {
		case <-ctx.Done():
			_ = left.Close()
			_ = right.Close()
			for remaining := completed; remaining < 2; remaining++ {
				<-results
			}
			return ctx.Err()
		case result := <-results:
			if firstErr == nil && result.err != nil && !errors.Is(result.err, io.EOF) {
				firstErr = result.err
			}
		}
	}
	return firstErr
}

func relayOne(destination io.Writer, source io.Reader, results chan<- relayResult) {
	_, err := io.Copy(destination, source)
	if closer, ok := destination.(closeWriter); ok {
		_ = closer.CloseWrite()
	}
	results <- relayResult{err: err}
}
