//go:build linux

// Package watch observes file activity under the shell's mounted roots in
// record mode, using inotify on the host-side sources of the bind mounts
// (inotify is inode based, so accesses made through the shell's mounts are
// reported here).
package watch

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"golang.org/x/sys/unix"
)

// Root is one watched mount: the variable name and the host directory.
type Root struct {
	Var string // e.g. ${APP_DATA}
	Dir string
}

// Watcher records file events into an evidence recorder.
type Watcher struct {
	fd   int
	mu   sync.Mutex
	wds  map[int]struct{ v, dir, rel string }
	rec  *evidence.Recorder
	done chan struct{}
	stop atomic.Bool
}

const mask = unix.IN_OPEN | unix.IN_ACCESS | unix.IN_MODIFY | unix.IN_CLOSE_WRITE | unix.IN_CREATE |
	unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB

// Start begins watching roots recursively.
func Start(roots []Root, rec *evidence.Recorder) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	w := &Watcher{fd: fd, wds: map[int]struct{ v, dir, rel string }{}, rec: rec, done: make(chan struct{})}
	for _, r := range roots {
		w.addTree(r.Var, r.Dir, "")
	}
	go w.loop()
	return w, nil
}

func (w *Watcher) addTree(v, base, rel string) {
	dir := filepath.Join(base, rel)
	// List the directory before watching it so the watcher's own scan is
	// never reported as the app's activity.
	ents, _ := os.ReadDir(dir)
	wd, err := unix.InotifyAddWatch(w.fd, dir, mask|unix.IN_ONLYDIR)
	if err != nil {
		return
	}
	w.mu.Lock()
	w.wds[wd] = struct{ v, dir, rel string }{v, base, rel}
	w.mu.Unlock()
	for _, e := range ents {
		if e.IsDir() {
			w.addTree(v, base, filepath.Join(rel, e.Name()))
		}
	}
}

func (w *Watcher) loop() {
	defer close(w.done)
	buf := make([]byte, 64<<10)
	for {
		stopping := w.stop.Load()
		pfd := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		n, err := unix.Read(w.fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			if stopping {
				return
			}
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
			off += unix.SizeofInotifyEvent + int(ev.Len)
			name := string(trimNul(nameBytes))
			w.mu.Lock()
			info, ok := w.wds[int(ev.Wd)]
			w.mu.Unlock()
			if !ok {
				continue
			}
			rel := filepath.Join(info.rel, name)
			if rel == "" {
				rel = "."
			}
			op := "read"
			if ev.Mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_ATTRIB) != 0 {
				op = "write"
			}
			if ev.Mask&(unix.IN_OPEN|unix.IN_ACCESS|unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_ATTRIB) == 0 {
				continue
			}
			if ev.Mask&unix.IN_CREATE != 0 && ev.Mask&unix.IN_ISDIR != 0 {
				w.addTree(info.v, info.dir, rel)
			}
			w.rec.Add(evidence.Event{Channel: evidence.ChanFile, Root: info.v, Path: filepath.ToSlash(rel), Op: op})
		}
	}
}

func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// Stop ends watching after draining pending events.
func (w *Watcher) Stop() {
	w.stop.Store(true)
	<-w.done
	unix.Close(w.fd)
}
