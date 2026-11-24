// Package ledger is the append-only audit ledger. Every entry carries the
// hash of the previous entry, so editing, deleting or reordering past
// entries is detectable with Verify. A separate head file records the
// sequence number and hash of the last entry, so cutting entries off the
// end is detectable too. The ledger lives in the core's state directory,
// which is never mounted into a shell.
//
// Limits: the chain has no secret. Anyone who can write the state
// directory (in particular any process running as the same OS user) can
// rewrite the whole chain and the head file consistently. Verify detects
// accidental damage and edits by parties that do not also rewrite the
// head; against the same user only a head value kept elsewhere (printed by
// `warp ledger verify`) can reveal a rewrite.
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

// Head is the position of the last entry, kept in <ledger>.head.
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// HeadPath returns the head file of a ledger.
func HeadPath(path string) string { return path + ".head" }

func writeHead(path string, h Head) error {
	b, err := json.Marshal(&h)
	if err != nil {
		return err
	}
	tmp := HeadPath(path) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, HeadPath(path))
}

func readHead(path string) (*Head, error) {
	b, err := os.ReadFile(HeadPath(path))
	if err != nil {
		return nil, err
	}
	var h Head
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("尾端錨點無法解析：%w", err)
	}
	return &h, nil
}

// checkTail compares the last entry with the head file. The only accepted
// states are "head == last entry" and "head one behind" (a crash between
// writing the entry and the head).
func checkTail(path string, last *Entry) error {
	head, err := readHead(path)
	if errors.Is(err, os.ErrNotExist) {
		if last == nil {
			return nil
		}
		return fmt.Errorf("帳本有 %d 筆紀錄卻找不到尾端錨點 %s：無法確認帳本尾端沒有被截斷，拒絕續寫", last.Seq, HeadPath(path))
	}
	if err != nil {
		return err
	}
	switch {
	case last != nil && last.Seq == head.Seq && last.Hash == head.Hash:
		return nil
	case last != nil && last.Seq == head.Seq+1 && last.Prev == head.Hash:
		return nil
	case last == nil || last.Seq < head.Seq:
		n := uint64(0)
		if last != nil {
			n = last.Seq
		}
		return fmt.Errorf("帳本尾端被截斷：錨點記錄到第 %d 筆，帳本只剩 %d 筆；拒絕續寫", head.Seq, n)
	}
	return fmt.Errorf("帳本最後一筆（第 %d 筆）與尾端錨點（第 %d 筆）不符；拒絕續寫", last.Seq, head.Seq)
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
	// Never continue a chain whose end does not match the head: otherwise
	// a truncation would be hidden by the next legitimate entry.
	if err := checkTail(l.path, last); err != nil {
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
	// Still under the lock: the head moves with every entry. A crash
	// between the two writes leaves the head exactly one entry behind.
	if err := writeHead(l.path, Head{Seq: e.Seq, Hash: e.Hash}); err != nil {
		return fmt.Errorf("無法更新帳本尾端錨點：%w", err)
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
	Head    Head // last entry
	hashAt  map[uint64]string
}

// HashAt returns the hash of entry seq ("" if there is none). It lets a
// head value kept outside the state directory be checked later.
func (r *VerifyResult) HashAt(seq uint64) string { return r.hashAt[seq] }

// Verify re-computes the whole hash chain and checks it against the head
// file, which detects entries cut off the end.
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
	hashAt := map[uint64]string{}
	res := &VerifyResult{hashAt: hashAt}
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
		hashAt[e.Seq] = e.Hash
		res.Entries++
		switch e.Decision {
		case "allow":
			res.Allow++
		case "deny":
			res.Deny++
		}
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	res.Head = Head{Seq: seq, Hash: prev}
	head, err := readHead(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if res.Entries > 0 {
			return res, fmt.Errorf("找不到帳本尾端錨點 %s：無法確認帳本尾端沒有被截斷", HeadPath(path))
		}
		return res, nil
	case err != nil:
		return res, err
	}
	if head.Seq > seq {
		return res, fmt.Errorf("帳本尾端被截斷：錨點記錄到第 %d 筆，帳本只剩 %d 筆", head.Seq, seq)
	}
	if hashAt[head.Seq] != head.Hash {
		return res, fmt.Errorf("帳本與尾端錨點不符（第 %d 筆的雜湊不同）：帳本被截斷後又續寫，或被整段改寫", head.Seq)
	}
	if seq-head.Seq > 1 {
		return res, fmt.Errorf("尾端錨點落後 %d 筆：錨點之後的條目不是由核心正常寫入的", seq-head.Seq)
	}
	return res, nil
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
