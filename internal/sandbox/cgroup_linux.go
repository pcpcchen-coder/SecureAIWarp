//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Cgroup is a best-effort per-shell cgroup (v2 or v1 pids+memory).
type Cgroup struct {
	dirs    []string
	Applied []string // human readable list of applied limits
}

func ownCgroupPaths() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "" {
			out["unified"] = parts[2]
			continue
		}
		for _, c := range strings.Split(parts[1], ",") {
			out[c] = parts[2]
		}
	}
	return out
}

// NewCgroup tries to create a cgroup limiting memory and pids. It returns a
// cgroup with an empty Applied list if nothing could be set up; callers fall
// back to rlimits and report the gap honestly.
func NewCgroup(name string, memBytes int64, pids int) *Cgroup {
	cg := &Cgroup{}
	own := ownCgroupPaths()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		dir := filepath.Join("/sys/fs/cgroup", own["unified"], name)
		if err := os.Mkdir(dir, 0o755); err == nil {
			ok := false
			if memBytes > 0 && os.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(memBytes, 10)), 0) == nil {
				cg.Applied = append(cg.Applied, fmt.Sprintf("memory.max=%d (cgroup v2)", memBytes))
				ok = true
			}
			if pids > 0 && os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(pids)), 0) == nil {
				cg.Applied = append(cg.Applied, fmt.Sprintf("pids.max=%d (cgroup v2)", pids))
				ok = true
			}
			if ok {
				cg.dirs = append(cg.dirs, dir)
			} else {
				os.Remove(dir)
			}
		}
		return cg
	}
	try := func(ctrl, file, val, label string) {
		base := filepath.Join("/sys/fs/cgroup", ctrl)
		if _, err := os.Stat(base); err != nil {
			return
		}
		dir := filepath.Join(base, own[ctrl], name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			dir = filepath.Join(base, name)
			if err := os.Mkdir(dir, 0o755); err != nil {
				return
			}
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(val), 0); err != nil {
			os.Remove(dir)
			return
		}
		if ctrl == "memory" {
			_ = os.WriteFile(filepath.Join(dir, "memory.memsw.limit_in_bytes"), []byte(val), 0)
		}
		cg.dirs = append(cg.dirs, dir)
		cg.Applied = append(cg.Applied, label)
	}
	if memBytes > 0 {
		try("memory", "memory.limit_in_bytes", strconv.FormatInt(memBytes, 10), fmt.Sprintf("memory=%d (cgroup v1)", memBytes))
	}
	if pids > 0 {
		try("pids", "pids.max", strconv.Itoa(pids), fmt.Sprintf("pids.max=%d (cgroup v1)", pids))
	}
	return cg
}

// Has reports whether a limit for the given controller was applied.
func (c *Cgroup) Has(prefix string) bool {
	for _, a := range c.Applied {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// Add moves a process into the cgroup.
func (c *Cgroup) Add(pid int) error {
	for _, d := range c.dirs {
		if err := os.WriteFile(filepath.Join(d, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the cgroup directories (they must be empty).
func (c *Cgroup) Remove() {
	for _, d := range c.dirs {
		_ = os.Remove(d)
	}
}
