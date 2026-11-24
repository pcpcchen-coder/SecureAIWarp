package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTraceKeyMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_STATE_DIR", dir)
	k1, err := TraceKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v", err)
	}
	k2, err := TraceKey()
	if err != nil || string(k1) != string(k2) {
		t.Fatalf("reuse: %v", err)
	}
	p := filepath.Join(dir, "trace.key")
	os.Chmod(p, 0o644)
	if _, err := TraceKey(); err == nil {
		t.Fatal("a world-readable key must be refused")
	}
	os.Chmod(p, 0o600)
	// A symlink to a key elsewhere is refused as well.
	other := filepath.Join(t.TempDir(), "k")
	os.WriteFile(other, k1, 0o600)
	os.Remove(p)
	os.Symlink(other, p)
	if _, err := TraceKey(); err == nil {
		t.Fatal("a symlinked key must be refused")
	}
}
