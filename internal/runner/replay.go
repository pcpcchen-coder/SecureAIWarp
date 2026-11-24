package runner

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/state"
)

// Evidence replay re-runs the command behind every cited trace in record
// mode on this machine and checks that each grant's behaviour shows up
// again. It trusts nothing in the trace files except the command to run:
// signatures, events and the agent-written evidence entries are all
// re-derived. This is what makes evidence checkable by someone who does
// not trust the account (or the machine) that produced it.

// ReplayOptions configure a replay.
type ReplayOptions struct {
	AppRoot      string
	ManifestPath string
	Picks        map[string]string // optional synthetic data per USER_PICK
	Timeout      time.Duration     // per command
	Stderr       io.Writer         // app output and progress
}

// ReplayGrant is the outcome for one grant cited from a trace.
type ReplayGrant struct {
	Grant      string
	Reproduced bool
	Why        string
}

// ReplayCommand is the outcome for one cited trace.
type ReplayCommand struct {
	Trace       string // observed_in
	Command     string // what was re-run
	SignatureOK bool   // the trace verifies with this user's local key
	ExitCode    int
	Err         string
	Grants      []ReplayGrant
}

// ReplayReport is the full replay result.
type ReplayReport struct {
	Commands []ReplayCommand
}

// AllReproduced reports whether every cited grant was reproduced.
func (r *ReplayReport) AllReproduced() bool {
	n := 0
	for _, c := range r.Commands {
		for _, g := range c.Grants {
			if !g.Reproduced {
				return false
			}
			n++
		}
	}
	return n > 0
}

// Replay runs the evidence replay.
func Replay(opt ReplayOptions) (*ReplayReport, error) {
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 60 * time.Second
	}
	root, err := ResolveAppRoot(opt.AppRoot)
	if err != nil {
		return nil, err
	}
	mp := opt.ManifestPath
	if mp == "" {
		mp = filepath.Join(root, ".warp", "warp.yaml")
	}
	l, err := manifest.LoadFile(mp)
	if err != nil {
		return nil, err
	}
	m := l.Manifest
	digest, err := manifest.ComputeDigest(root)
	if err != nil {
		return nil, err
	}
	if digest != m.App.Digest {
		return nil, fmt.Errorf("應用內容雜湊（%s）與宣告的 app.digest 不同；重放只對宣告所描述的應用內容有意義", digest)
	}
	key, _ := state.TraceKey()

	// Group the cited grants by trace.
	byTrace := map[string][]string{}
	for _, ev := range m.Evidence {
		if m.GrantExists(ev.Grant) {
			byTrace[ev.ObservedIn] = append(byTrace[ev.ObservedIn], ev.Grant)
		}
	}
	if len(byTrace) == 0 {
		return nil, errors.New("宣告中沒有任何證據可重放")
	}
	var traces []string
	for t := range byTrace {
		traces = append(traces, t)
	}
	sort.Strings(traces)

	// Synthetic data for every picked folder (unless given) and the
	// declared access mode.
	picks, rw := map[string]string{}, map[string]bool{}
	tmp, err := os.MkdirTemp("", "warp-replay-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, f := range m.Files {
		kind, pick, _ := manifest.PathVar(f.Path)
		if kind != "USER_PICK" {
			continue
		}
		rw[pick] = f.Mode == "rw"
		if p, ok := opt.Picks[pick]; ok {
			picks[pick] = p
			continue
		}
		d := filepath.Join(tmp, "pick-"+pick)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(d, "sample.txt"), []byte("synthetic replay data\n"), 0o644); err != nil {
			return nil, err
		}
		picks[pick] = d
	}

	rep := &ReplayReport{}
	for i, rel := range traces {
		rc := ReplayCommand{Trace: rel}
		t, err := loadCitedTrace(root, rel)
		if err != nil {
			rc.Err = err.Error()
			for _, g := range byTrace[rel] {
				rc.Grants = append(rc.Grants, ReplayGrant{Grant: g, Why: "無法讀取側錄檔"})
			}
			rep.Commands = append(rep.Commands, rc)
			continue
		}
		rc.Command = evidence.CommandString(t.Command)
		rc.SignatureOK = key != nil && evidence.Verify(t, key) == nil
		fmt.Fprintf(opt.Stderr, "warp：重放 %s：%s\n", rel, rc.Command)
		dir := filepath.Join(tmp, fmt.Sprintf("run-%d", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
		res, err := Run(Options{
			Mode: ModeRecord, AppRoot: root, ManifestPath: mp, Command: t.Command,
			Picks: picks, PicksRW: rw, TraceDir: dir, Timeout: opt.Timeout, DeclaredOnly: true,
			// A served UI is visited once, as a person opening the printed
			// URL would; anything beyond that needs manual replay.
			IngressNotify: func(_ int, url string) {
				go func() {
					if resp, err := client.Get(url); err == nil {
						io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
						resp.Body.Close()
					}
				}()
			},
			Stdin: strings.NewReader(""), Stdout: opt.Stderr, Stderr: opt.Stderr,
		})
		var nt *evidence.Trace
		if err == nil && res != nil && res.TracePath != "" {
			rc.ExitCode = res.ExitCode
			nt, err = evidence.Load(res.TracePath, mustKey(key))
		}
		if err != nil {
			rc.Err = err.Error()
		}
		for _, g := range byTrace[rel] {
			rg := ReplayGrant{Grant: g}
			switch {
			case nt == nil:
				rg.Why = "重放沒有產生側錄紀錄"
			default:
				rg.Why = manifest.EvidenceMatches(m, g, nt)
				rg.Reproduced = rg.Why == ""
			}
			rc.Grants = append(rc.Grants, rg)
		}
		rep.Commands = append(rep.Commands, rc)
	}
	return rep, nil
}

func mustKey(k []byte) []byte {
	if k == nil {
		return []byte{}
	}
	return k
}

// loadCitedTrace reads a trace cited by observed_in (same path rules as
// lint) without trusting its signature.
func loadCitedTrace(root, rel string) (*evidence.Trace, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") || !strings.HasPrefix(filepath.ToSlash(filepath.Clean(rel)), ".warp/evidence/") {
		return nil, fmt.Errorf("observed_in 必須位於 .warp/evidence/")
	}
	return evidence.LoadUnverified(filepath.Join(root, filepath.Clean(rel)))
}

// PrintReplay renders a replay report.
func PrintReplay(w io.Writer, r *ReplayReport) {
	for _, c := range r.Commands {
		sig := "本機簽章有效"
		if !c.SignatureOK {
			sig = "本機簽章無效或不是本機產生（不影響重放結果）"
		}
		fmt.Fprintf(w, "【%s】%s\n  重放指令：%s\n", c.Trace, sig, orNone(c.Command))
		if c.Err != "" {
			fmt.Fprintf(w, "  ! %s\n", c.Err)
		}
		for _, g := range c.Grants {
			if g.Reproduced {
				fmt.Fprintf(w, "  ✔ 重現  %s\n", g.Grant)
			} else {
				fmt.Fprintf(w, "  ✖ 未重現 %s：%s\n", g.Grant, g.Why)
			}
		}
	}
}

func orNone(s string) string {
	if s == "" {
		return "（無）"
	}
	return s
}
