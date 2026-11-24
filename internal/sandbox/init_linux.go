//go:build linux

package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// InitArg is the hidden argv[1] that selects the shell init.
const InitArg = "__shell-init"

// ExecArg is the hidden argv[1] of the short-lived exec helper: it applies
// the app's resource limits to itself and then execve()s the app. The
// app's limits (memory in particular) must never be applied to the init
// itself: a Go runtime that cannot grow its heap aborts, taking the whole
// shell down.
const ExecArg = "__shell-exec"

// ctlFD is the control socket inherited by the shell init (ExtraFiles[0]).
const ctlFD = 3

// selfFD holds the warp binary, opened before pivot_root, so the init can
// re-exec it as the exec helper without the binary being mounted in the
// shell. It is close-on-exec: the app never inherits it.
var selfFD = -1

// RunInit is the entry point of the re-executed binary inside the new
// namespaces. It never returns.
func RunInit() {
	m, _, err := recvMsg(ctlFD)
	if err != nil || m.T != "config" || m.Config == nil {
		fatalInit(fmt.Sprintf("無法讀取殼設定：%v", err))
	}
	cfg := m.Config
	if selfFD, err = unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0); err != nil {
		fatalInit("無法開啟核心執行檔：" + err.Error())
	}
	if err := setupFS(cfg); err != nil {
		fatalInit("建立合成檔案系統失敗：" + err.Error())
	}
	if err := loopbackUp(); err != nil {
		fatalInit("無法啟用殼內迴路介面：" + err.Error())
	}
	if cfg.Hostname != "" {
		_ = unix.Sethostname([]byte(cfg.Hostname))
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort))
	if err != nil {
		fatalInit("無法建立殼內代理入口：" + err.Error())
	}
	lf, err := ln.(*net.TCPListener).File()
	if err != nil {
		fatalInit(err.Error())
	}
	ln.Close()
	if err := sendMsg(ctlFD, &msg{T: "ready"}, int(lf.Fd())); err != nil {
		fatalInit(err.Error())
	}
	lf.Close()
	// Wait for the parent's go.
	m, _, err = recvMsg(ctlFD)
	if err != nil || m.T != "start" {
		fatalInit("父程序未送出啟動指令")
	}
	// The init stays non-dumpable so the app cannot ptrace it or read its
	// /proc files.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, unix.SIGCHLD, unix.SIGTERM, unix.SIGINT, unix.SIGHUP)

	pid, err := startApp(cfg)
	if err != nil {
		fatalInit("無法啟動應用：" + err.Error())
	}
	var sendMu sync.Mutex
	send := func(m *msg, fd int) {
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = sendMsg(ctlFD, m, fd)
	}
	send(&msg{T: "started", ID: pid}, -1)

	go func() {
		for {
			m, _, err := recvMsg(ctlFD)
			if err != nil {
				// Parent is gone: tear everything down (fail closed).
				unix.Kill(-1, unix.SIGKILL)
				os.Exit(137)
			}
			switch m.T {
			case "dial":
				go func(id, port int) {
					c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
					if err != nil {
						send(&msg{T: "dialed", ID: id, Err: err.Error()}, -1)
						return
					}
					f, err := c.(*net.TCPConn).File()
					c.Close()
					if err != nil {
						send(&msg{T: "dialed", ID: id, Err: err.Error()}, -1)
						return
					}
					send(&msg{T: "dialed", ID: id}, int(f.Fd()))
					f.Close()
				}(m.ID, m.Port)
			case "signal":
				_ = unix.Kill(-pid, syscall.Signal(m.Sig))
			}
		}
	}()

	for s := range sigs {
		if s != unix.SIGCHLD {
			_ = unix.Kill(-pid, s.(syscall.Signal))
			continue
		}
		for {
			var ws unix.WaitStatus
			wpid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if err != nil || wpid <= 0 {
				break
			}
			if wpid == pid {
				code := ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
				send(&msg{T: "exit", Code: code}, -1)
				// Exiting as PID 1 kills every remaining process in the shell.
				os.Exit(code)
			}
		}
	}
}

func fatalInit(s string) {
	fmt.Fprintln(os.Stderr, "warp（殼內）："+s)
	_ = sendMsg(ctlFD, &msg{T: "error", Err: s}, -1)
	os.Exit(126)
}

// startApp drops every capability on a dedicated, locked OS thread and
// forks the app from it, so the app starts with an empty capability
// bounding set, no ambient capabilities and no_new_privs.
func startApp(cfg *Config) (int, error) {
	type res struct {
		pid int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		// Never unlocked: the thread exits with this goroutine and its
		// reduced credentials are never reused by the runtime.
		runtime.LockOSThread()
		pid, err := dropAndFork(cfg)
		ch <- res{pid, err}
	}()
	r := <-ch
	return r.pid, r.err
}

func dropAndFork(cfg *Config) (int, error) {
	for c := 0; c <= 63; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			return 0, fmt.Errorf("drop bounding cap %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
		return 0, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 0, err
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capset: %w", err)
	}
	path, err := lookPath(cfg.Argv[0], cfg.Env)
	if err != nil {
		return 0, err
	}
	// The app is started through the exec helper (a fresh copy of this
	// binary), which applies the resource limits and then execs the app.
	lims, err := json.Marshal(cfg.Rlimits)
	if err != nil {
		return 0, err
	}
	argv := append([]string{"warp-exec", ExecArg, string(lims), path}, cfg.Argv...)
	return syscall.ForkExec(fmt.Sprintf("/proc/self/fd/%d", selfFD), argv, &syscall.ProcAttr{
		Dir:   cfg.Cwd,
		Env:   cfg.Env,
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
}

// RunExec is the entry point of the exec helper. It runs with no
// capabilities and no_new_privs (inherited from the init's dropped thread),
// applies every resource limit to itself and replaces itself with the app.
// Any failure aborts the start: the app never runs without its limits.
func RunExec(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "warp（殼內）：exec helper: bad arguments")
		os.Exit(126)
	}
	var lims []Rlimit
	if err := json.Unmarshal([]byte(args[0]), &lims); err != nil {
		fmt.Fprintln(os.Stderr, "warp（殼內）：exec helper:", err)
		os.Exit(126)
	}
	for _, r := range lims {
		lim := unix.Rlimit{Cur: r.Cur, Max: r.Max}
		if err := unix.Setrlimit(r.Resource, &lim); err != nil {
			fmt.Fprintf(os.Stderr, "warp（殼內）：無法設定資源上限 %d：%v\n", r.Resource, err)
			os.Exit(126)
		}
	}
	err := unix.Exec(args[1], args[2:], os.Environ())
	fmt.Fprintf(os.Stderr, "warp（殼內）：無法啟動應用 %s：%v\n", args[1], err)
	os.Exit(126)
}

func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	pathVar := ""
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathVar = e[5:]
		}
	}
	for _, dir := range filepath.SplitList(pathVar) {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("殼內找不到指令 %q", name)
}

// ---- file system ----

const (
	stRdonly     = 0x1
	stNoexec     = 0x8
	stNoatime    = 0x400
	stNodiratime = 0x800
	stRelatime   = 0x1000
)

func lockedFlags(dst string) (uintptr, bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dst, &st); err != nil {
		return 0, false, err
	}
	var f uintptr
	if st.Flags&stNoexec != 0 {
		f |= unix.MS_NOEXEC
	}
	if st.Flags&stNoatime != 0 {
		f |= unix.MS_NOATIME
	}
	if st.Flags&stNodiratime != 0 {
		f |= unix.MS_NODIRATIME
	}
	if st.Flags&stRelatime != 0 {
		f |= unix.MS_RELATIME
	}
	return f, st.Flags&stRdonly != 0, nil
}

// mountPointsUnder lists dst and every mount point below it.
func mountPointsUnder(dst string) []string {
	out := []string{dst}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMount(fields[4])
		if strings.HasPrefix(mp, dst+"/") {
			out = append(out, mp)
		}
	}
	return out
}

func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// bind bind-mounts src on dst and remounts it (and every submount) with
// nosuid, optional nodev and read-only unless writable.
func bind(src, dst string, writable, nodev bool) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", src, dst, err)
	}
	for _, mp := range mountPointsUnder(dst) {
		lf, ro, err := lockedFlags(mp)
		if err != nil {
			return err
		}
		flags := unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | lf
		if nodev {
			flags |= unix.MS_NODEV
		}
		if !writable {
			flags |= unix.MS_RDONLY
		} else if ro {
			return fmt.Errorf("%s 位於唯讀檔案系統，無法提供可寫掛載", src)
		}
		if err := unix.Mount("", mp, "", uintptr(flags), ""); err != nil {
			// A submount we cannot remount read-only would stay writable:
			// fail closed.
			return fmt.Errorf("remount %s: %w", mp, err)
		}
	}
	return nil
}

func mkMountTarget(dst string, isDir bool) error {
	if isDir {
		return os.MkdirAll(dst, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func setupFS(cfg *Config) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	R := cfg.RootDir
	if err := unix.Mount("tmpfs", R, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=16m,mode=0755"); err != nil {
		return fmt.Errorf("mount root tmpfs: %w", err)
	}
	// System directories (read-only).
	for _, d := range cfg.SystemDirs {
		st, err := os.Lstat(d)
		if err != nil {
			continue
		}
		dst := filepath.Join(R, d)
		if st.Mode()&os.ModeSymlink != 0 {
			t, err := os.Readlink(d)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(t, dst); err != nil {
				return err
			}
			continue
		}
		if !st.IsDir() {
			continue
		}
		if err := mkMountTarget(dst, true); err != nil {
			return err
		}
		if err := bind(d, dst, false, true); err != nil {
			return err
		}
	}
	// /etc: only an allow-list from the host plus generated files.
	if err := os.MkdirAll(filepath.Join(R, "etc"), 0o755); err != nil {
		return err
	}
	for _, e := range cfg.EtcCopy {
		st, err := os.Lstat(e)
		if err != nil {
			continue
		}
		dst := filepath.Join(R, e)
		if st.Mode()&os.ModeSymlink != 0 {
			t, err := os.Readlink(e)
			if err != nil {
				return err
			}
			_ = os.MkdirAll(filepath.Dir(dst), 0o755)
			if err := os.Symlink(t, dst); err != nil {
				return err
			}
			continue
		}
		if err := mkMountTarget(dst, st.IsDir()); err != nil {
			return err
		}
		if err := bind(e, dst, false, true); err != nil {
			return err
		}
	}
	for inner, src := range cfg.Generated {
		dst := filepath.Join(R, inner)
		if err := mkMountTarget(dst, false); err != nil {
			return err
		}
		if err := bind(src, dst, false, true); err != nil {
			return err
		}
	}
	// /proc for the new PID namespace.
	if err := os.MkdirAll(filepath.Join(R, "proc"), 0o555); err != nil {
		return err
	}
	if err := unix.Mount("proc", filepath.Join(R, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	// Defence in depth: forbid nested user namespaces inside the shell. They
	// cannot unlock our read-only mounts, but they expose a large amount of
	// kernel code to the app. The limit is per user namespace and owned by
	// this init.
	for _, f := range []string{"user/max_user_namespaces", "user/max_net_namespaces"} {
		if err := os.WriteFile(filepath.Join(R, "proc/sys", f), []byte("0"), 0); err != nil {
			fmt.Fprintf(os.Stderr, "warp（殼內）：警告：無法設定 %s=0：%v\n", f, err)
		}
	}
	// /dev with a minimal set of device nodes.
	dev := filepath.Join(R, "dev")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "size=64k,mode=0755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	for _, n := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		src := "/dev/" + n
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(dev, n)
		if err := mkMountTarget(dst, false); err != nil {
			return err
		}
		if err := bind(src, dst, true, false); err != nil {
			return err
		}
	}
	for name, target := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(target, filepath.Join(dev, name)); err != nil {
			return err
		}
	}
	shm := filepath.Join(dev, "shm")
	if err := os.MkdirAll(shm, 0o1777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", shm, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=64m,mode=1777"); err != nil {
		return fmt.Errorf("mount /dev/shm: %w", err)
	}
	// Private /tmp.
	tmp := filepath.Join(R, "tmp")
	if err := os.MkdirAll(tmp, 0o1777); err != nil {
		return err
	}
	tsize := cfg.TmpSize
	if tsize <= 0 {
		tsize = 256 << 20
	}
	if err := unix.Mount("tmpfs", tmp, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, fmt.Sprintf("size=%d,mode=1777", tsize)); err != nil {
		return fmt.Errorf("mount /tmp: %w", err)
	}
	// The app, read-only, with hidden entries masked.
	app := filepath.Join(R, cfg.AppTarget)
	if err := mkMountTarget(app, true); err != nil {
		return err
	}
	if err := bind(cfg.AppRoot, app, false, true); err != nil {
		return err
	}
	for _, h := range cfg.Hide {
		p := filepath.Join(app, h)
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			if err := unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0555"); err != nil {
				return fmt.Errorf("mask %s: %w", h, err)
			}
		} else {
			if err := unix.Mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("mask %s: %w", h, err)
			}
		}
	}
	// Declared mounts.
	for _, b := range cfg.Binds {
		st, err := os.Stat(b.Source)
		if err != nil {
			return fmt.Errorf("掛載來源 %s：%w", b.Source, err)
		}
		dst := filepath.Join(R, b.Target)
		if err := mkMountTarget(dst, st.IsDir()); err != nil {
			return err
		}
		if err := bind(b.Source, dst, b.Writable, true); err != nil {
			return err
		}
	}
	// /dev tmpfs becomes read-only now that nodes are in place.
	if err := unix.Mount("", dev, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NOEXEC, "size=64k,mode=0755"); err != nil {
		return fmt.Errorf("remount /dev ro: %w", err)
	}
	// Switch root and drop every reference to the host tree.
	old := filepath.Join(R, ".oldroot")
	if err := os.Mkdir(old, 0o700); err != nil {
		return err
	}
	if err := unix.Chdir(R); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", ".oldroot"); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := os.Remove("/.oldroot"); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "size=16m,mode=0755"); err != nil {
		return fmt.Errorf("remount / ro: %w", err)
	}
	if cfg.Cwd != "" {
		if err := unix.Chdir(cfg.Cwd); err != nil {
			return err
		}
	}
	return nil
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
