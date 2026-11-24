package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckHostMount(t *testing.T) {
	home, _ := os.UserHomeDir()
	ok := t.TempDir()
	withSSH := t.TempDir()
	os.Mkdir(filepath.Join(withSSH, ".ssh"), 0o700)
	withSock := t.TempDir()
	os.WriteFile(filepath.Join(withSock, "docker.sock"), nil, 0o600)
	state := t.TempDir()
	if err := checkHostMount("x", ok, []string{state}); err != nil {
		t.Fatalf("plain dir: %v", err)
	}
	for name, p := range map[string]string{"root": "/", "etc": "/etc", "usr": "/usr", "home": home,
		"home-like": withSSH, "control socket": withSock, "state": state, "inside state": filepath.Join(state, "x")} {
		os.MkdirAll(p, 0o755)
		if err := checkHostMount("x", p, []string{state}); err == nil {
			t.Errorf("%s (%s) must be refused", name, p)
		}
	}
	if err := checkHostMount("x", filepath.Join(home, ".ssh"), nil); err == nil {
		if _, serr := os.Stat(filepath.Join(home, ".ssh")); serr == nil {
			t.Errorf("~/.ssh must be refused")
		}
	}
}
