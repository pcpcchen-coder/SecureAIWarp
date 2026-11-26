package draft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

func TestDraftFromTraces(t *testing.T) {
	key := []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "main.py"), []byte("x"), 0o644)
	dir := filepath.Join(root, ".warp", "evidence")
	os.MkdirAll(dir, 0o755)
	digest, _ := manifest.ComputeDigest(root)
	tr := &evidence.Trace{Format: evidence.Format, ID: "trace-0001", Command: []string{"python3", "main.py"}, AppDigest: digest, Events: []evidence.Event{
		{Channel: "file", Root: "${USER_PICK:in}", Path: "a", Op: "read"},
		{Channel: "file", Root: "${APP_DATA}", Path: "o", Op: "write"},
		{Channel: "egress", Host: "api.example.com", Port: 443, Decision: "allowed"},
		{Channel: "egress", Host: "telemetry.example.net", Port: 443, Decision: "blocked", Reason: "x"},
		{Channel: "secret", Name: "K", Host: "api.example.com", Location: "header", Header: "authorization"},
		{Channel: "ingress", Port: 9000},
	}}
	if err := evidence.Write(filepath.Join(dir, "trace-0001.json"), tr, key); err != nil {
		t.Fatal(err)
	}
	d, err := FromDir(root, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(d.YAML)
	if err != nil {
		t.Fatalf("draft must parse strictly: %v\n%s", err, d.YAML)
	}
	res := manifest.Lint(m, manifest.Options{AppRoot: root, TraceKey: key})
	for _, f := range res.Findings {
		if f.Level == manifest.LevelError && f.Rule != "grant-purpose" {
			t.Errorf("only placeholder purposes may fail: %+v", f)
		}
	}
	s := strings.ReplaceAll(string(d.YAML), PurposePlaceholder, "用途")
	m2, _ := manifest.Parse([]byte(s))
	if r := manifest.Lint(m2, manifest.Options{AppRoot: root, TraceKey: key}); r.Errors() != 0 {
		t.Fatalf("filled draft should lint clean: %+v", r.Findings)
	}
	if m.Files[0].Path != "${APP_DATA}" || m.Files[0].Mode != "rw" || m.Files[1].Mode != "ro" {
		t.Errorf("files: %+v", m.Files)
	}
	// A listener alone does not decide the app kind (tests often start
	// throw-away servers); the notes say which command listened.
	if len(m.Network.Egress) != 1 || m.App.Kind != "cli" || len(m.DeniedByDesign) != 1 {
		t.Errorf("egress/kind/denied: %+v %s %+v", m.Network.Egress, m.App.Kind, m.DeniedByDesign)
	}
	if !noteHas(d, "9000 埠）來自側錄中的監聽：python3 main.py") || !noteHas(d, "請確認 app.entry") || m.App.Version != "0.1.0" || !noteHas(d, "暫填 0.1.0") {
		t.Errorf("notes: %q version %s", d.Notes, m.App.Version)
	}
}

func noteHas(d *Draft, sub string) bool {
	for _, n := range d.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func TestDraftFailedTracesVersionAndURLSecrets(t *testing.T) {
	key := []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"x","version":"2.3.4"}`), 0o644)
	dir := filepath.Join(root, ".warp", "evidence")
	os.MkdirAll(dir, 0o755)
	digest, _ := manifest.ComputeDigest(root)
	write := func(id string, code int, cmd []string, ev ...evidence.Event) {
		tr := &evidence.Trace{Format: evidence.Format, ID: id, Command: cmd, AppDigest: digest, ExitCode: code, Events: ev}
		if err := evidence.Write(filepath.Join(dir, id+".json"), tr, key); err != nil {
			t.Fatal(err)
		}
	}
	write("trace-0001", 0, []string{"node", "--test"},
		evidence.Event{Channel: "egress", Host: "api.example.com", Port: 443, Decision: "allowed"},
		evidence.Event{Channel: "secret", Name: "K", Host: "api.example.com", Location: "url"})
	write("trace-0002", 1, []string{"node", "app.js", "--clear-cache"},
		evidence.Event{Channel: "egress", Host: "failed.example.com", Port: 443, Decision: "allowed"})
	write("trace-0003", 130, []string{"node", "server.js"},
		evidence.Event{Channel: "ingress", Port: 3000})
	d, err := FromDir(root, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := manifest.Parse(d.YAML)
	if m.App.Version != "2.3.4" {
		t.Errorf("version from package.json: %q", m.App.Version)
	}
	if strings.Contains(string(d.YAML), "failed.example.com") || !noteHas(d, "trace-0002.json（結束碼 1") {
		t.Errorf("a failed trace must not be used by default:\n%s\n%q", d.YAML, d.Notes)
	}
	if len(m.Network.Ingress) != 1 || strings.Join(m.App.Entry, " ") != "node server.js" {
		t.Errorf("an interrupted server trace is used: %+v %v", m.Network.Ingress, m.App.Entry)
	}
	if len(m.Secrets) != 0 || !noteHas(d, "無法授權") || noteHas(d, "只能改為 app-visible") {
		t.Errorf("url-only secret: %+v %q", m.Secrets, d.Notes)
	}
	d, _ = FromDirWith(root, dir, key, Options{IncludeFailed: true})
	if !strings.Contains(string(d.YAML), "failed.example.com") || !noteHas(d, "--include-failed") {
		t.Errorf("--include-failed must use and flag the failed trace")
	}
	os.Remove(filepath.Join(root, "package.json"))
	os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[build-system]\nversion = \"9\"\n[project]\nname = \"x\"\nversion = \"1.0.2\"  # c\n"), 0o644)
	if v, src := appVersion(root); v != "1.0.2" || src != "pyproject.toml" {
		t.Errorf("pyproject version: %q %q", v, src)
	}
}
