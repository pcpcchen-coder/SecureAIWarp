// Package report holds the machine-readable reports the core writes under
// .warp/reports/ (enforce runs and probe results). The label generator only
// trusts a report when it matches the current manifest and app digest.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Probe statuses.
const (
	Blocked        = "blocked"
	Penetrated     = "penetrated"
	Error          = "error"
	NotImplemented = "not-implemented"
)

// Resource limit scopes: how much of the shell a limit actually bounds.
const (
	ScopeShell   = "shell"   // the whole shell together (cgroup, or a per-namespace count)
	ScopeProcess = "process" // each process separately (rlimit); the shell total is not bounded
	ScopeFile    = "file"    // each file separately
	ScopeNone    = "none"    // not enforced
)

// ResourceLimit records how one declared resource limit was enforced in a
// run, so the label can report what actually held on this machine.
type ResourceLimit struct {
	Resource  string `json:"resource"` // memory|pids|disk|cpu
	Limit     string `json:"limit"`
	Scope     string `json:"scope"`
	Mechanism string `json:"mechanism"`
}

// CurrentIdentity describes the OS identity the core runs as.
func CurrentIdentity() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	return fmt.Sprintf("uid=%d", os.Geteuid())
}

// ProbeItem is the outcome of one deterministic probe.
type ProbeItem struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// Probe is the full probe report.
type Probe struct {
	Time           string          `json:"time"`
	Core           string          `json:"core"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	AppDigest      string          `json:"app_digest"`
	RunID          string          `json:"run_id"`
	Identity       string          `json:"identity,omitempty"`
	Resources      []ResourceLimit `json:"resources,omitempty"`
	Items          []ProbeItem     `json:"items"`
}

// Counts returns blocked, total implemented and not-implemented counts.
func (p *Probe) Counts() (blocked, total, notImpl int) {
	for _, it := range p.Items {
		switch it.Status {
		case NotImplemented:
			notImpl++
		case Blocked:
			blocked++
			total++
		default:
			total++
		}
	}
	return
}

// AllBlocked reports whether every implemented probe was blocked.
func (p *Probe) AllBlocked() bool {
	b, t, _ := p.Counts()
	return t > 0 && b == t
}

// Enforce is written after every enforce run.
type Enforce struct {
	Time           string          `json:"time"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	AppDigest      string          `json:"app_digest"`
	Command        []string        `json:"command"`
	ExitCode       int             `json:"exit_code"`
	Denied         int             `json:"denied"`
	Identity       string          `json:"identity,omitempty"`
	Resources      []ResourceLimit `json:"resources,omitempty"`
}

// Dir returns the reports directory of an app.
func Dir(appRoot string) string { return filepath.Join(appRoot, ".warp", "reports") }

func write(appRoot, name string, v any) error {
	if err := os.MkdirAll(Dir(appRoot), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(Dir(appRoot), name), append(b, '\n'), 0o644)
}

// WriteProbe writes probe.json.
func WriteProbe(appRoot string, p *Probe) error {
	if p.Time == "" {
		p.Time = time.Now().UTC().Format(time.RFC3339)
	}
	return write(appRoot, "probe.json", p)
}

// WriteEnforce writes enforce-last.json.
func WriteEnforce(appRoot string, e *Enforce) error {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	return write(appRoot, "enforce-last.json", e)
}

func read(appRoot, name string, v any) bool {
	b, err := os.ReadFile(filepath.Join(Dir(appRoot), name))
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// LoadProbe reads probe.json if present.
func LoadProbe(appRoot string) *Probe {
	var p Probe
	if read(appRoot, "probe.json", &p) {
		return &p
	}
	return nil
}

// LoadEnforce reads enforce-last.json if present.
func LoadEnforce(appRoot string) *Enforce {
	var e Enforce
	if read(appRoot, "enforce-last.json", &e) {
		return &e
	}
	return nil
}
