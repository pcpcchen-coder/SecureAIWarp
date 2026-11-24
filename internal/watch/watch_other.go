//go:build !linux

package watch

import (
	"errors"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
)

// Root is one watched mount.
type Root struct {
	Var string
	Dir string
}

// Watcher is unavailable on this platform.
type Watcher struct{}

// Start always fails on this platform.
func Start([]Root, *evidence.Recorder) (*Watcher, error) {
	return nil, errors.New("file watching is only implemented on Linux")
}

// Stop is a no-op.
func (w *Watcher) Stop() {}
