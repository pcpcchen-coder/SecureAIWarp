// Package ledger is the append-only audit ledger. Every entry carries the
// hash of the previous entry, so editing, deleting or reordering past
// entries is detectable with Verify. The ledger lives in the core's state
// directory, which is never mounted into a shell.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Genesis is the prev-hash of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one gate decision or lifecycle event.
type Entry struct {
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"`
	Run      string `json:"run"`
	Mode     string `json:"mode"`
	Channel  string `json:"channel"`  // file|egress|ingress|secret|process|probe|run
	Action   string `json:"action"`   // connect|http|request|start|exit|...
	Decision string `json:"decision"` // allow|deny|info
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

func entryHash(e *Entry) string {
	c := *e
	c.Hash = ""
	b, _ := json.Marshal(&c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ledger appends entries to one file.
type Ledger struct {
	mu   sync.Mutex
	path string
	f    *os.File
	run  string
	mode string
	// OnAppend, if set, is called for every appended entry (used by probe).
	OnAppend func(Entry)
}

// Open opens (or creates) the ledger file.
func Open(path, run, mode string) (*Ledger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("無法開啟稽核帳本：%w", err)
	}
	return &Ledger{path: path, f: f, run: run, mode: mode}, nil
}

// Path returns the ledger file path.
func (l *Ledger) Path() string { return l.path }

// Close closes the ledger.
func (l *Ledger) Close() error { return l.f.Close() }

// lastEntry reads the final line of the file.
func lastEntry(f *os.File) (*Entry, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}
	chunk := int64(64 << 10)
	for {
		if chunk > size {
			chunk = size
		}
		buf := make([]byte, chunk)
		if _, err := f.ReadAt(buf, size-chunk); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		buf = bytes.TrimRight(buf, "\n")
		i := bytes.LastIndexByte(buf, '\n')
		if i >= 0 || chunk == size {
			line := buf[i+1:]
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return nil, fmt.Errorf("帳本最後一筆無法解析（帳本可能已損毀）：%w", err)
			}
			return &e, nil
		}
		chunk *= 2
	}
}

// Append writes one entry, chaining it to the current last entry. A file
// lock serialises concurrent writers (several runs of the same app).
func (l *Ledger) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := unix.Flock(int(l.f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	last, err := lastEntry(l.f)
	if err != nil {
		return err
	}
	e.Prev = Genesis
	e.Seq = 1
	if last != nil {
		e.Prev = last.Hash
		e.Seq = last.Seq + 1
	}
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Run == "" {
		e.Run = l.run
	}
	if e.Mode == "" {
		e.Mode = l.mode
	}
	e.Hash = entryHash(&e)
	b, err := json.Marshal(&e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if l.OnAppend != nil {
		l.OnAppend(e)
	}
	return nil
}

// Log is a convenience wrapper that ignores (but reports to stderr) errors.
// A failing ledger write is reported loudly; callers that must fail closed
// use Append directly.
func (l *Ledger) Log(channel, action, decision, target, detail string) {
	if l == nil {
		return
	}
	if err := l.Append(Entry{Channel: channel, Action: action, Decision: decision, Target: target, Detail: detail}); err != nil {
		fmt.Fprintf(os.Stderr, "warp: 警告：寫入稽核帳本失敗：%v\n", err)
	}
}

// VerifyResult summarises a verification pass.
type VerifyResult struct {
	Entries int
	Allow   int
	Deny    int
}

// Verify re-computes the whole hash chain.
func Verify(path string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	prev := Genesis
	var seq uint64
	res := &VerifyResult{}
	line := 0
	for sc.Scan() {
		line++
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return res, fmt.Errorf("第 %d 行無法解析：%w", line, err)
		}
		if e.Prev != prev {
			return res, fmt.Errorf("第 %d 行（seq %d）的前一筆雜湊不符：帳本被刪改或重排", line, e.Seq)
		}
		if e.Seq != seq+1 {
			return res, fmt.Errorf("第 %d 行序號不連續（%d 之後出現 %d）", line, seq, e.Seq)
		}
		if entryHash(&e) != e.Hash {
			return res, fmt.Errorf("第 %d 行（seq %d）內容雜湊不符：此筆已被修改", line, e.Seq)
		}
		prev, seq = e.Hash, e.Seq
		res.Entries++
		switch e.Decision {
		case "allow":
			res.Allow++
		case "deny":
			res.Deny++
		}
	}
	return res, sc.Err()
}

// ReadAll returns all entries (no verification).
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
