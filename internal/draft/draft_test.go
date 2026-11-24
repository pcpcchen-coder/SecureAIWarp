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
	tr := &evidence.Trace{Format: evidence.Format, ID: "trace-0001", Command: []string{"python3", "main.py"}, Events: []evidence.Event{
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
	if len(m.Network.Egress) != 1 || m.App.Kind != "local-web" || len(m.DeniedByDesign) != 1 {
		t.Errorf("egress/kind/denied: %+v %s %+v", m.Network.Egress, m.App.Kind, m.DeniedByDesign)
	}
}
