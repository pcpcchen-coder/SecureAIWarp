//go:build !linux

package sandbox

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// InitArg is the hidden argv[1] that selects the shell init.
const InitArg = "__shell-init"

// Shell is unavailable on this platform.
type Shell struct{}

// Cgroup is unavailable on this platform.
type Cgroup struct{ Applied []string }

// Stdio for the shell.
type Stdio struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// NewCgroup returns an empty cgroup.
func NewCgroup(string, int64, int) *Cgroup { return &Cgroup{} }

// Has always reports false.
func (c *Cgroup) Has(string) bool { return false }

// Remove is a no-op.
func (c *Cgroup) Remove() {}

// Preflight always fails: there is no process backend on this platform.
func Preflight() error { return ErrUnsupported }

// Start always fails closed.
func Start(*Config, *Cgroup, Stdio) (*Shell, error) { return nil, ErrUnsupported }

// RunInit is never used on this platform.
func RunInit() { os.Exit(126) }

// EgressListener is never available.
func (s *Shell) EgressListener() net.Listener { return nil }

// InitPid is never available.
func (s *Shell) InitPid() int { return 0 }

// Run always fails.
func (s *Shell) Run() error { return ErrUnsupported }

// DialApp always fails.
func (s *Shell) DialApp(int, time.Duration) (net.Conn, error) { return nil, ErrUnsupported }

// Signal is a no-op.
func (s *Shell) Signal(syscall.Signal) {}

// Kill is a no-op.
func (s *Shell) Kill() {}

// Wait always fails.
func (s *Shell) Wait() (int, error) { return 125, ErrUnsupported }

// Done is closed immediately.
func (s *Shell) Done() <-chan struct{} { c := make(chan struct{}); close(c); return c }
