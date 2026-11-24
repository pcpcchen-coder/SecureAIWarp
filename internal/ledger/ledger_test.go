package ledger

import (
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
	}
	for name, content := range mutations {
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := Verify(p); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}
