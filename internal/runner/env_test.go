package runner

import (
	"io"
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

func shellEnv(t *testing.T, mode string, m *manifest.Manifest) map[string]string {
	t.Helper()
	s := &session{opt: Options{Mode: mode, Stderr: io.Discard}, m: m, runID: "test-" + randHex(4)}
	defer s.close()
	if err := s.buildConfig(nil); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, kv := range s.cfg.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

func TestShellProxyEnv(t *testing.T) {
	withEgress := &manifest.Manifest{Network: manifest.Network{Egress: []manifest.Egress{{Host: "api.example.com", Port: 443}}}}
	offline := &manifest.Manifest{}
	for _, c := range []struct {
		mode string
		m    *manifest.Manifest
		node bool
	}{{ModeRecord, nil, true}, {ModeRecord, offline, true}, {ModeEnforce, withEgress, true}, {ModeEnforce, offline, false}, {ModeProbe, offline, false}} {
		env := shellEnv(t, c.mode, c.m)
		if env["HTTPS_PROXY"] != "http://"+ProxyAddr || env["http_proxy"] != "http://"+ProxyAddr {
			t.Errorf("%s: proxy not set: %v", c.mode, env)
		}
		// Loopback inside the shell is the shell's own (separate network
		// namespace), so it bypasses the gate; nothing else does.
		for _, k := range []string{"NO_PROXY", "no_proxy"} {
			if env[k] != "localhost,127.0.0.1,::1" {
				t.Errorf("%s: %s=%q", c.mode, k, env[k])
			}
		}
		if _, got := env["NODE_USE_ENV_PROXY"]; got != c.node {
			t.Errorf("%s (egress=%v): NODE_USE_ENV_PROXY set=%v, want %v", c.mode, c.m != nil && len(c.m.Network.Egress) > 0, got, c.node)
		}
	}
}

func TestExpandCommand(t *testing.T) {
	s := &session{opt: Options{Mode: ModeEnforce}, command: []string{"tool", "--in", "${USER_PICK:notes}", "--db=${APP_DATA}/x.db"},
		mounts: []mount{{varName: manifest.VarAppData, shell: ShellData}, {varName: manifest.PickVar("notes"), shell: ShellPickBase + "/notes"}}}
	argv, err := s.expandCommand()
	if err != nil || strings.Join(argv, " ") != "tool --in /warp/pick/notes --db=/warp/data/x.db" {
		t.Fatalf("got %q %v", argv, err)
	}
	if strings.Join(s.command, " ") != "tool --in ${USER_PICK:notes} --db=${APP_DATA}/x.db" {
		t.Fatalf("the recorded command must stay unexpanded: %q", s.command)
	}
	s.command = []string{"tool", "${APP_CACHE}"}
	if _, err := s.expandCommand(); err == nil {
		t.Fatalf("an unmounted placeholder must be refused")
	}
}
