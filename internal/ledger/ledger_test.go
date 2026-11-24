package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainDetectsTampering(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := Open(p, "run1", "enforce")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l.Log("egress", "connect", []string{"allow", "deny"}[i%2], "evil.example:443", "")
	}
	l.Close()
	// A second writer continues the same chain.
	l2, _ := Open(p, "run2", "enforce")
	l2.Log("run", "start", "info", "", "")
	l2.Close()
	r, err := Verify(p)
	if err != nil || r.Entries != 6 || r.Deny != 2 || r.Allow != 3 {
		t.Fatalf("verify: %+v %v", r, err)
	}
	orig, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	mutations := map[string]string{
		"edit":          strings.Replace(string(orig), `"decision":"deny"`, `"decision":"allow"`, 1),
		"delete":        strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "\n") + "\n",
		"reorder":       strings.Join(append([]string{lines[1], lines[0]}, lines[2:]...), "\n") + "\n",
		"truncate-head": strings.Join(lines[1:], "\n") + "\n",
		"truncate-tail": strings.Join(lines[:len(lines)-2], "\n") + "\n",
		"truncate-all":  "",
	}
	for name, content := range mutations {
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := Verify(p); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}

// TestTailTruncation: cutting entries off the end is detected by the head
// file, a later legitimate append refuses to hide it, a missing head is not
// silently accepted, and a crash between entry and head is tolerated.
func TestTailTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, _ := Open(p, "run1", "enforce")
	for i := 0; i < 4; i++ {
		if err := l.Append(Entry{Channel: "egress", Action: "connect", Decision: "deny"}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	r, err := Verify(p)
	if err != nil || r.Head.Seq != 4 {
		t.Fatalf("verify: %+v %v", r, err)
	}
	orig, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")

	// Truncate the last entry: Verify fails, and the next append refuses
	// to continue (and thereby hide) the shortened chain.
	os.WriteFile(p, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o600)
	if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "截斷") {
		t.Fatalf("tail truncation not detected: %v", err)
	}
	l2, _ := Open(p, "run2", "enforce")
	if err := l2.Append(Entry{Channel: "run", Action: "start", Decision: "info"}); err == nil {
		t.Fatal("append after truncation must be refused")
	}
	l2.Close()
	if _, err := Verify(p); err == nil {
		t.Fatal("truncation must stay detectable after a refused append")
	}

	// Deleting the head file as well is not accepted silently.
	os.Remove(HeadPath(p))
	if _, err := Verify(p); err == nil {
		t.Fatal("a missing head must fail verification")
	}
	l3, _ := Open(p, "run3", "enforce")
	if err := l3.Append(Entry{Channel: "run", Action: "start", Decision: "info"}); err == nil {
		t.Fatal("append without a head must be refused")
	}
	l3.Close()

	// Crash between writing the entry and the head: head one behind is OK,
	// and appending continues normally.
	os.WriteFile(p, orig, 0o600)
	var e3 Entry
	json.Unmarshal([]byte(lines[2]), &e3)
	b, _ := json.Marshal(Head{Seq: 3, Hash: e3.Hash})
	os.WriteFile(HeadPath(p), b, 0o600)
	if _, err := Verify(p); err != nil {
		t.Fatalf("head one behind (crash) must verify: %v", err)
	}
	l4, _ := Open(p, "run4", "enforce")
	if err := l4.Append(Entry{Channel: "run", Action: "start", Decision: "info"}); err != nil {
		t.Fatalf("append after crash: %v", err)
	}
	l4.Close()
	if r, err := Verify(p); err != nil || r.Head.Seq != 5 {
		t.Fatalf("after crash recovery: %+v %v", r, err)
	}
}
