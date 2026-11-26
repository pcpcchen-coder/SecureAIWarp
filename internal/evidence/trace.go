// Package evidence defines record-mode traces. Traces are written by the
// core and signed (HMAC) with a per-user key kept outside every shell.
//
// What the signature does and does not mean: it shows the file was written
// with this OS user's key and not modified since, so the app inside the
// shell, other OS users and accidental edits cannot produce or alter a
// valid trace. It does NOT keep out a process running as the same OS user
// (such as the fitting agent), which can read the key; and even an honest
// trace only shows that some command, run under the core, exhibited the
// behaviour. The command is therefore part of the evidence (shown on the
// label), and `warp evidence replay` re-runs it instead of trusting files.
package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Format is the trace format version.
const Format = "0.1"

// Channels.
const (
	ChanFile    = "file"
	ChanEgress  = "egress"
	ChanIngress = "ingress"
	ChanSecret  = "secret"
	ChanProcess = "process"
)

// Event is one observed behaviour. Events are de-duplicated and counted.
type Event struct {
	Channel  string `json:"channel"`
	Root     string `json:"root,omitempty"`     // file: ${APP_DATA}, ${USER_PICK:x}
	Path     string `json:"path,omitempty"`     // file: path relative to root
	Op       string `json:"op,omitempty"`       // file: read|write; egress: connect|http
	Host     string `json:"host,omitempty"`     // egress/secret
	Port     int    `json:"port,omitempty"`     // egress/ingress
	Decision string `json:"decision,omitempty"` // egress: allowed|blocked
	Reason   string `json:"reason,omitempty"`
	Name     string `json:"name,omitempty"`     // secret name
	Location string `json:"location,omitempty"` // secret: header|url|body
	Header   string `json:"header,omitempty"`   // secret: header name (lower case)
	Exe      string `json:"exe,omitempty"`      // process
	Count    int    `json:"count"`
}

func (e Event) key() string {
	return strings.Join([]string{e.Channel, e.Root, e.Path, e.Op, e.Host, strconv.Itoa(e.Port),
		e.Decision, e.Name, e.Location, e.Header, e.Exe}, "\x00")
}

// Trace is a signed record of one record-mode run.
type Trace struct {
	Format    string   `json:"warp_trace"`
	ID        string   `json:"id"`
	CreatedAt string   `json:"created_at"`
	Command   []string `json:"command"`
	AppDigest string   `json:"app_digest"`
	ExitCode  int      `json:"exit_code"`
	Events    []Event  `json:"events"`
	Signature string   `json:"signature"`
}

// Recorder collects events concurrently.
type Recorder struct {
	mu     sync.Mutex
	events map[string]*Event
	order  []string
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{events: map[string]*Event{}} }

// Add records an event (nil-safe).
func (r *Recorder) Add(e Event) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := e.key()
	if ex, ok := r.events[k]; ok {
		ex.Count++
		return
	}
	e.Count = 1
	r.events[k] = &e
	r.order = append(r.order, k)
}

// Events returns the collected events in first-seen order.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, *r.events[k])
	}
	return out
}

func signPayload(t *Trace) ([]byte, error) {
	c := *t
	c.Signature = ""
	return json.Marshal(&c)
}

// Sign sets the trace signature.
func Sign(t *Trace, key []byte) error {
	b, err := signPayload(t)
	if err != nil {
		return err
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	t.Signature = "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
	return nil
}

// Verify checks the trace signature.
func Verify(t *Trace, key []byte) error {
	b, err := signPayload(t)
	if err != nil {
		return err
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	want := "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(t.Signature)) {
		return errors.New("側錄檔簽章不符（不是由本機核心產生，或已被修改）")
	}
	return nil
}

// Load reads and verifies a trace file.
func Load(path string, key []byte) (*Trace, error) {
	t, err := LoadUnverified(path)
	if err != nil {
		return nil, err
	}
	if err := Verify(t, key); err != nil {
		return nil, err
	}
	return t, nil
}

// LoadUnverified parses a trace without checking its signature. Only
// evidence replay uses it: replay re-runs the trace's command under this
// core and trusts nothing else in the file.
func LoadUnverified(path string) (*Trace, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Trace
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("側錄檔格式錯誤：%w", err)
	}
	if t.Format != Format {
		return nil, fmt.Errorf("不支援的側錄檔版本 %q", t.Format)
	}
	return &t, nil
}

var traceName = regexp.MustCompile(`^trace-(\d{4,})\.json$`)

// seqFile keeps the highest trace number ever handed out in a directory, so
// that numbers are not reused after traces are moved out of it.
const seqFile = ".trace-seq"

// NextPath returns the next trace-NNNN.json path in dir: one more than the
// highest number present or ever handed out there.
func NextPath(dir string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	max := 0
	for _, e := range ents {
		if m := traceName.FindStringSubmatch(e.Name()); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > max {
				max = n
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, seqFile)); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > max {
			max = n
		}
	}
	id := fmt.Sprintf("trace-%04d", max+1)
	if err := os.WriteFile(filepath.Join(dir, seqFile), []byte(strconv.Itoa(max+1)+"\n"), 0o644); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, id+".json"), id, nil
}

// Write signs and writes a trace exclusively (never overwrites).
func Write(path string, t *Trace, key []byte) error {
	if err := Sign(t, key); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// ListTraces returns the trace files in dir sorted by name.
func ListTraces(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if traceName.MatchString(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// CommandString renders an argv for humans, quoting arguments so that the
// rendering is unambiguous (`sh -c 'a; b'` is not shown as `sh -c a; b`).
// It is what triggered_by must contain and what labels display.
func CommandString(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.IndexFunc(a, func(r rune) bool {
			return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '=' || r == ',' || r == '+' || r == '@' || r == '%' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
		}) < 0 {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}

// HostMatches reports whether host matches a manifest host pattern. A
// pattern "*.example.com" matches any strict subdomain of example.com.
func HostMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, base) && len(host) > len(base)
	}
	return pattern == host
}

// HasFile reports whether the trace observed file activity under root;
// needWrite requires at least one write.
func (t *Trace) HasFile(root string, needWrite bool) bool {
	for _, e := range t.Events {
		if e.Channel == ChanFile && e.Root == root && (!needWrite || e.Op == "write") {
			return true
		}
	}
	return false
}

// HasEgress reports whether the trace observed a connection to host:port.
func (t *Trace) HasEgress(pattern string, port int) bool {
	for _, e := range t.Events {
		if e.Channel == ChanEgress && e.Port == port && HostMatches(pattern, e.Host) {
			return true
		}
	}
	return false
}

// HasIngress reports whether the trace observed a listener on port.
func (t *Trace) HasIngress(port int) bool {
	for _, e := range t.Events {
		if e.Channel == ChanIngress && e.Port == port {
			return true
		}
	}
	return false
}

// HasSecret reports whether the decoy for name was sent to host in header.
func (t *Trace) HasSecret(name, host, header string) bool {
	for _, e := range t.Events {
		if e.Channel == ChanSecret && e.Name == name && e.Location == "header" &&
			strings.EqualFold(e.Header, header) && HostMatches(host, e.Host) {
			return true
		}
	}
	return false
}
