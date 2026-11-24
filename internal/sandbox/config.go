// Package sandbox implements the `process` isolation backend: a re-exec of
// the warp binary into fresh Linux user, mount, network, PID, IPC, UTS and
// cgroup namespaces. Inside, a synthetic root file system is assembled from
// read-only system directories, the read-only app, and only the declared
// writable mounts. The network namespace has nothing but loopback; the only
// way out is a listening socket created inside the namespace and handed to
// the parent (the egress gate) over a unix socket (SCM_RIGHTS).
package sandbox

import "errors"

// Bind is one bind mount into the shell.
type Bind struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Writable bool   `json:"writable"`
}

// Rlimit is one resource limit applied before the app starts.
type Rlimit struct {
	Resource int    `json:"resource"`
	Cur      uint64 `json:"cur"`
	Max      uint64 `json:"max"`
}

// Config fully describes a shell. It contains no secrets: secret values
// never reach the shell except as placeholders inside Env.
type Config struct {
	RootDir    string            `json:"root_dir"`   // empty host dir; a tmpfs is mounted on it
	AppRoot    string            `json:"app_root"`   // host path of the app (mounted read-only)
	AppTarget  string            `json:"app_target"` // e.g. /app
	Hide       []string          `json:"hide"`       // top-level app entries masked in the shell
	SystemDirs []string          `json:"system_dirs"`
	EtcCopy    []string          `json:"etc_copy"`  // /etc entries bound read-only from the host if present
	Generated  map[string]string `json:"generated"` // shell path -> host staging file (bound read-only)
	Binds      []Bind            `json:"binds"`
	Env        []string          `json:"env"`
	Argv       []string          `json:"argv"`
	Cwd        string            `json:"cwd"`
	ProxyPort  int               `json:"proxy_port"`
	TmpSize    int64             `json:"tmp_size"`
	Rlimits    []Rlimit          `json:"rlimits"`
	Hostname   string            `json:"hostname"`
}

// ErrUnsupported is returned on platforms without the process backend.
var ErrUnsupported = errors.New("此平台尚未支援 process 隔離後端（目前只支援 Linux）；拒絕在無隔離的情況下執行")
