//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Shell is a running process-backend shell seen from the parent.
type Shell struct {
	cmd      *exec.Cmd
	ctl      int
	sendMu   sync.Mutex
	mu       sync.Mutex
	nextID   int
	pending  map[int]chan dialResult
	listener net.Listener
	exitCode int
	exited   chan struct{}
	started  chan struct{}
	startOne sync.Once
	initErr  string
	waitErr  error
	waitOnce sync.Once
}

type dialResult struct {
	conn net.Conn
	err  error
}

// Stdio for the shell.
type Stdio struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Preflight checks that the kernel lets us create the namespaces we need.
func Preflight() error {
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		return fmt.Errorf("核心不支援使用者命名空間：%w", err)
	}
	return nil
}

// Start launches the shell init, applies the cgroup (if any), sends the
// configuration and waits until the egress listener is handed over. The
// app itself starts only after Run is called.
func Start(cfg *Config, cg *Cgroup, stdio Stdio) (*Shell, error) {
	if err := Preflight(); err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	child := os.NewFile(uintptr(fds[1]), "warp-ctl")
	cmd := exec.Command("/proc/self/exe", InitArg)
	cmd.Env = []string{"WARP_INTERNAL=shell-init"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdio.Stdin, stdio.Stdout, stdio.Stderr
	cmd.ExtraFiles = []*os.File{child}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | unix.CLONE_NEWCGROUP,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		child.Close()
		unix.Close(fds[0])
		return nil, fmt.Errorf("無法建立隔離命名空間：%w", err)
	}
	child.Close()
	s := &Shell{cmd: cmd, ctl: fds[0], pending: map[int]chan dialResult{}, exited: make(chan struct{}), started: make(chan struct{})}
	fail := func(e error) (*Shell, error) {
		s.Kill()
		s.wait()
		return nil, e
	}
	if cg != nil {
		if err := cg.Add(cmd.Process.Pid); err != nil {
			return fail(fmt.Errorf("無法把殼加入 cgroup：%w", err))
		}
	}
	if err := sendMsg(s.ctl, &msg{T: "config", Config: cfg}, -1); err != nil {
		return fail(err)
	}
	m, fd, err := recvMsg(s.ctl)
	if err != nil {
		return fail(fmt.Errorf("殼初始化失敗：%w", err))
	}
	if m.T != "ready" || fd < 0 {
		if fd >= 0 {
			unix.Close(fd)
		}
		return fail(fmt.Errorf("殼初始化失敗：%s", m.Err))
	}
	f := os.NewFile(uintptr(fd), "egress-listener")
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return fail(err)
	}
	s.listener = ln
	go s.readLoop()
	return s, nil
}

// EgressListener is the listening socket that lives inside the shell's
// network namespace; accepting on it yields the app's proxy connections.
func (s *Shell) EgressListener() net.Listener { return s.listener }

// InitPid is the host PID of the shell init (PID 1 inside).
func (s *Shell) InitPid() int { return s.cmd.Process.Pid }

// Run tells the init to start the app and waits until it has started.
func (s *Shell) Run() error {
	s.sendMu.Lock()
	err := sendMsg(s.ctl, &msg{T: "start"}, -1)
	s.sendMu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-s.started:
		return nil
	case <-s.exited:
		if s.initErr != "" {
			return errors.New(s.initErr)
		}
		return errors.New("殼在應用啟動前結束")
	}
}

func (s *Shell) readLoop() {
	defer func() {
		s.wait()
		s.mu.Lock()
		for id, ch := range s.pending {
			ch <- dialResult{err: errors.New("殼已結束")}
			delete(s.pending, id)
		}
		s.mu.Unlock()
		close(s.exited)
	}()
	gotExit := false
	for {
		m, fd, err := recvMsg(s.ctl)
		if err != nil {
			if !gotExit {
				s.exitCode = 125
			}
			return
		}
		switch m.T {
		case "started":
			// Once only: a repeated message must never crash the core.
			s.startOne.Do(func() { close(s.started) })
			if fd >= 0 {
				unix.Close(fd)
			}
		case "dialed":
			s.mu.Lock()
			ch := s.pending[m.ID]
			delete(s.pending, m.ID)
			s.mu.Unlock()
			var r dialResult
			if fd >= 0 {
				f := os.NewFile(uintptr(fd), "app-conn")
				r.conn, r.err = net.FileConn(f)
				f.Close()
			} else {
				r.err = errors.New(m.Err)
			}
			if ch != nil {
				ch <- r
			} else if r.conn != nil {
				r.conn.Close()
			}
		case "exit":
			gotExit = true
			s.exitCode = m.Code
		case "error":
			s.initErr = m.Err
			s.exitCode = 126
			if fd >= 0 {
				unix.Close(fd)
			}
		default:
			if fd >= 0 {
				unix.Close(fd)
			}
		}
	}
}

func (s *Shell) wait() {
	s.waitOnce.Do(func() {
		s.waitErr = s.cmd.Wait()
		unix.Close(s.ctl)
	})
}

// DialApp connects to a TCP port the app listens on inside the shell. The
// connect happens inside the shell's network namespace (by the init) and
// the connected socket is passed back.
func (s *Shell) DialApp(port int, timeout time.Duration) (net.Conn, error) {
	ch := make(chan dialResult, 1)
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.pending[id] = ch
	s.mu.Unlock()
	s.sendMu.Lock()
	err := sendMsg(s.ctl, &msg{T: "dial", ID: id, Port: port}, -1)
	s.sendMu.Unlock()
	if err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(timeout):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, errors.New("連入殼內逾時")
	}
}

// Signal forwards a signal to the app's process group.
func (s *Shell) Signal(sig syscall.Signal) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	_ = sendMsg(s.ctl, &msg{T: "signal", Sig: int(sig)}, -1)
}

// Kill terminates the whole shell (every process in its PID namespace).
func (s *Shell) Kill() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

// Wait blocks until the shell exits and returns the app's exit code.
func (s *Shell) Wait() (int, error) {
	<-s.exited
	if s.initErr != "" {
		return s.exitCode, errors.New(s.initErr)
	}
	return s.exitCode, nil
}

// Done is closed when the shell has exited.
func (s *Shell) Done() <-chan struct{} { return s.exited }
