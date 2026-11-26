package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// fixture builds an app root with one signed trace covering every grant of
// base() and returns the root.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "app.py"), []byte("print(1)\n"), 0o644)
	dir := filepath.Join(root, ".warp", "evidence")
	os.MkdirAll(dir, 0o755)
	digest, err := ComputeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	tr := &evidence.Trace{Format: evidence.Format, ID: "trace-0001", Command: []string{"python3", "app.py"}, AppDigest: digest, Events: []evidence.Event{
		{Channel: "file", Root: "${APP_DATA}", Path: "x", Op: "write"},
		{Channel: "file", Root: "${USER_PICK:docs}", Path: "a", Op: "read"},
		{Channel: "egress", Host: "api.example.com", Port: 443, Decision: "allowed"},
		{Channel: "ingress", Port: 8080},
		{Channel: "secret", Name: "API_KEY", Host: "api.example.com", Location: "header", Header: "x-api-key"},
	}}
	if err := evidence.Write(filepath.Join(dir, "trace-0001.json"), tr, testKey); err != nil {
		t.Fatal(err)
	}
	return root
}

func base(t *testing.T, root string) *Manifest {
	d, err := ComputeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	ev := func(g string) Evidence {
		return Evidence{Grant: g, ObservedIn: ".warp/evidence/trace-0001.json", TriggeredBy: "python3 app.py"}
	}
	return &Manifest{
		Warp: "0.1",
		App:  App{Name: "demo", Version: "1.0.0", Kind: "local-web", Entry: []string{"python3", "app.py"}, Digest: d},
		Runtime: Runtime{Isolation: "process", Spawn: "none",
			Resources: Resources{Memory: "256Mi", Pids: 64, Disk: "100Mi"}},
		Files: []FileGrant{{Path: "${APP_DATA}", Mode: "rw", Purpose: "存設定"}, {Path: "${USER_PICK:docs}", Mode: "ro", Purpose: "讀文件"}},
		Network: Network{
			Egress:  []Egress{{Host: "api.example.com", Port: 443, Purpose: "呼叫 API"}},
			Ingress: []Ingress{{Listen: 8080, Expose: "loopback", Auth: "local-token", Purpose: "操作介面"}},
		},
		Secrets: []Secret{{Name: "API_KEY", ProvidedBy: "recipient", Visibility: "gate-only", Purpose: "API 金鑰",
			Bind: SecretBind{Host: "api.example.com", Inject: SecretInject{Header: "x-api-key"}}}},
		Exceptions: []Exception{},
		Evidence:   []Evidence{ev("files[0]"), ev("files[1]"), ev("network.egress[0]"), ev("network.ingress[0]"), ev("secrets[0]")},
	}
}

func lint(t *testing.T, root string, m *Manifest) *Result {
	return Lint(m, Options{AppRoot: root, TraceKey: testKey})
}

func hasRule(r *Result, level, rule string) bool {
	for _, f := range r.Findings {
		if f.Level == level && f.Rule == rule {
			return true
		}
	}
	return false
}

func TestBaseManifestIsClean(t *testing.T) {
	root := fixture(t)
	r := lint(t, root, base(t, root))
	if r.Errors() != 0 || r.Warnings() != 0 {
		t.Fatalf("expected clean, got %+v", r.Findings)
	}
	// Round trip through YAML keeps it clean.
	y, err := Marshal(base(t, root))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := Parse(y)
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, y)
	}
	if r := lint(t, root, m2); r.Errors() != 0 {
		t.Fatalf("round trip: %+v", r.Findings)
	}
}

func TestHardRules(t *testing.T) {
	root := fixture(t)
	cases := []struct {
		name string
		mut  func(m *Manifest)
		rule string
	}{
		{"global wildcard", func(m *Manifest) { m.Network.Egress[0].Host = "*" }, "egress-global-wildcard"},
		{"tld wildcard", func(m *Manifest) { m.Network.Egress[0].Host = "*.com" }, "egress-global-wildcard"},
		{"cidr", func(m *Manifest) { m.Network.Egress[0].Host = "10.0.0.0/8" }, "egress-global-wildcard"},
		{"metadata ip", func(m *Manifest) { m.Network.Egress[0].Host = "169.254.169.254" }, "egress-metadata"},
		{"metadata name", func(m *Manifest) { m.Network.Egress[0].Host = "metadata.google.internal" }, "egress-metadata"},
		{"loopback name", func(m *Manifest) { m.Network.Egress[0].Host = "localhost" }, "egress-loopback"},
		{"loopback ip", func(m *Manifest) { m.Network.Egress[0].Host = "127.0.0.1" }, "egress-loopback"},
		{"lan ip without flag", func(m *Manifest) { m.Network.Egress[0].Host = "192.168.1.10" }, "egress-lan"},
		{"public ingress without auth", func(m *Manifest) { m.Network.Ingress[0].Expose = "public"; m.Network.Ingress[0].Auth = "none" }, "ingress-auth"},
		{"high risk tool without gate", func(m *Manifest) {
			m.AI = &AI{Budget: &AIBudget{DailyUSD: 1}, Tools: []AITool{{Name: "send_email", Risk: "high"}}}
		}, "tool-gate"},
		{"risk floor", func(m *Manifest) {
			m.AI = &AI{Budget: &AIBudget{DailyUSD: 1}, Tools: []AITool{{Name: "deleteFile", Risk: "low"}}}
		}, "tool-risk-floor"},
		{"ai without budget", func(m *Manifest) { m.AI = &AI{Tools: []AITool{{Name: "lookup", Risk: "low"}}} }, "ai-budget"},
		{"missing evidence", func(m *Manifest) { m.Evidence = m.Evidence[1:] }, "grant-evidence"},
		{"missing purpose", func(m *Manifest) { m.Files[0].Purpose = "" }, "grant-purpose"},
		{"placeholder purpose", func(m *Manifest) { m.Files[0].Purpose = "（待填寫：用一句人話說明用途）" }, "grant-purpose"},
		{"evidence without behaviour", func(m *Manifest) { m.Network.Egress[0].Port = 8443 }, "grant-evidence"},
		{"rw needs write evidence", func(m *Manifest) { m.Files[1].Mode = "rw" }, "grant-evidence"},
		{"secret bind not in egress", func(m *Manifest) { m.Secrets[0].Bind.Host = "other.example.com" }, "secret-bind"},
		{"forbidden header", func(m *Manifest) { m.Secrets[0].Bind.Inject.Header = "Host" }, "secret-bind"},
		{"exception for hard rule", func(m *Manifest) {
			m.Exceptions = []Exception{{Rule: "egress-metadata", Grant: "network.egress[0]", Reason: "x", ApprovedBy: "a", ApprovedAt: "b"}}
		}, "exception"},
		{"digest mismatch", func(m *Manifest) { m.App.Digest = "sha256:" + strings.Repeat("0", 64) }, "app-digest"},
		{"absolute path", func(m *Manifest) { m.Files[1].Path = "/home/user/.ssh" }, "files-absolute"},
		{"evidence escapes evidence dir", func(m *Manifest) { m.Evidence[0].ObservedIn = "../../etc/passwd" }, "grant-evidence"},
		{"ingress on gate port", func(m *Manifest) { m.Network.Ingress[0].Listen = 3128 }, "format"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := base(t, root)
			c.mut(m)
			r := lint(t, root, m)
			if !hasRule(r, LevelError, c.rule) {
				t.Fatalf("expected error %s, got %+v", c.rule, r.Findings)
			}
		})
	}
}

func TestSoftRulesAndExceptions(t *testing.T) {
	root := fixture(t)
	m := base(t, root)
	m.Network.Egress[0].Host = "*.example.com"
	m.Secrets[0].Bind.Host = "api.example.com"
	m.Network.Egress = append(m.Network.Egress, Egress{Host: "api.example.com", Port: 443, Purpose: "x"})
	m.Evidence = append(m.Evidence, Evidence{Grant: "network.egress[1]", ObservedIn: ".warp/evidence/trace-0001.json", TriggeredBy: "python3 app.py"})
	r := lint(t, root, m)
	if r.Errors() != 0 || !hasRule(r, LevelWarning, SoftEgressSubdomain) {
		t.Fatalf("expected soft warning only, got %+v", r.Findings)
	}
	if len(r.Attention) != 1 || r.Attention[0].Excepted {
		t.Fatalf("attention: %+v", r.Attention)
	}
	m.Exceptions = []Exception{{Rule: SoftEgressSubdomain, Grant: "network.egress[0]", Reason: "CDN", ApprovedBy: "Alice", ApprovedAt: "2026-11-24"}}
	r = lint(t, root, m)
	if hasRule(r, LevelWarning, SoftEgressSubdomain) || !r.Attention[0].Excepted {
		t.Fatalf("exception should silence the warning: %+v", r.Findings)
	}
	m = base(t, root)
	m.Secrets[0].Visibility = "app-visible"
	if r := lint(t, root, m); !hasRule(r, LevelWarning, SoftSecretAppVisible) {
		t.Fatalf("app-visible should warn")
	}
}

func TestTamperedTraceRejected(t *testing.T) {
	root := fixture(t)
	p := filepath.Join(root, ".warp", "evidence", "trace-0001.json")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "api.example.com", "evil.example.com", 1)), 0o644)
	r := lint(t, root, base(t, root))
	if !hasRule(r, LevelError, "grant-evidence") {
		t.Fatalf("tampered trace must be rejected")
	}
	// A trace signed with another key is rejected too.
	root2 := fixture(t)
	if r := Lint(base(t, root2), Options{AppRoot: root2, TraceKey: []byte("another-key-another-key-another!!")}); !hasRule(r, LevelError, "grant-evidence") {
		t.Fatalf("foreign trace must be rejected")
	}
}

func TestParserIsClosed(t *testing.T) {
	good := "warp: \"0.1\"\napp:\n  name: x\nruntime:\n  isolation: process\n  spawn: none\n  background: false\nexceptions: []\nevidence: []\n"
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("good: %v", err)
	}
	bad := map[string]string{
		"unknown field":  good + "privileged: true\n",
		"nested unknown": strings.Replace(good, "  name: x\n", "  name: x\n  script: rm -rf /\n", 1),
		"alias":          good + "files:\n  - &a {path: \"${APP_DATA}\", mode: rw, purpose: p}\n  - *a\n",
		"two documents":  good + "---\n" + good,
		"wrong type":     strings.Replace(good, "background: false", "background: \"no\"", 1),
		"explicit tag":   strings.Replace(good, "name: x", "name: !!binary eA==", 1),
		"duplicate key":  good + "warp: \"0.2\"\n",
		"yaml 1.1 bool":  strings.Replace(good, "background: false", "background: no", 1),
		"string port":    good + "network:\n  egress:\n    - {host: a.example.com, port: \"443\", purpose: p}\n",
	}
	for name, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}

func TestExampleManifestParses(t *testing.T) {
	l, err := LoadFile(filepath.Join("..", "..", "examples", "invoice-helper.warp.yaml"))
	if err != nil {
		t.Fatalf("example manifest: %v", err)
	}
	r := Lint(l.Manifest, Options{})
	// Without the author's machine-local traces the evidence cannot verify;
	// everything else in the example must be well-formed.
	for _, f := range r.Findings {
		if f.Level == LevelError && f.Rule != "grant-evidence" && f.Rule != "app-digest" {
			t.Errorf("unexpected error in example: %+v", f)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1Ki": 1024, "512Mi": 512 << 20, "1Gi": 1 << 30, "10M": 10e6, "4096": 4096} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "1.5Gi", "abc", "0"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("%q should fail", in)
		}
	}
}

// TestEvidenceBinding: evidence is bound to the command the core actually
// ran and to the app content it was recorded on. An agent cannot describe
// a trace as coming from another command, nor reuse a trace recorded on
// different app content (for example a throwaway app written to produce
// the behaviour).
func TestEvidenceBinding(t *testing.T) {
	root := fixture(t)
	if r := lint(t, root, base(t, root)); r.Errors() != 0 {
		t.Fatalf("fixture must lint clean: %+v", r.Findings)
	}
	m := base(t, root)
	m.Evidence[2].TriggeredBy = "pytest tests/test_api.py"
	if r := lint(t, root, m); !hasRule(r, LevelError, "evidence-command") {
		t.Fatalf("a triggered_by that differs from the trace's command must be rejected")
	}
	// A validly signed trace recorded on other content (here: before the
	// app changed) no longer counts, even after app.digest is updated.
	os.WriteFile(filepath.Join(root, "app.py"), []byte("print(2)\n"), 0o644)
	m = base(t, root)
	if r := lint(t, root, m); !hasRule(r, LevelError, "evidence-stale") {
		t.Fatalf("a trace recorded on different app content must be rejected")
	}
}

func TestEntryPlaceholders(t *testing.T) {
	root := fixture(t)
	m := base(t, root)
	m.App.Entry = []string{"python3", "app.py", "--in", "${USER_PICK:docs}", "--db=${APP_DATA}/db.sqlite"}
	if r := lint(t, root, m); hasRule(r, LevelError, "entry-var") {
		t.Fatalf("declared placeholders must be accepted: %+v", r.Findings)
	}
	for _, bad := range []string{"${USER_PICK:other}", "${USER_PICK:Docs}", "${APP_CACHE}"} {
		m.App.Entry = []string{"python3", "app.py", bad}
		if r := lint(t, root, m); !hasRule(r, LevelError, "entry-var") {
			t.Errorf("%s in app.entry must be rejected", bad)
		}
	}
	m.App.Entry = []string{"sh", "-c", "echo ${HOME} $WARP_PICK_DOCS"}
	if r := lint(t, root, m); hasRule(r, LevelError, "entry-var") {
		t.Errorf("other ${...} text is not a placeholder")
	}
}

func TestExpandArgs(t *testing.T) {
	paths := map[string]string{"${APP_DATA}": "/warp/data", "${USER_PICK:docs}": "/warp/pick/docs"}
	got, err := ExpandArgs([]string{"x", "${USER_PICK:docs}", "--db=${APP_DATA}/a ${APP_DATA}", "${HOME}", "$APP_DATA"}, paths)
	want := []string{"x", "/warp/pick/docs", "--db=/warp/data/a /warp/data", "${HOME}", "$APP_DATA"}
	if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"${USER_PICK:other}", "${USER_PICK:BAD}", "${APP_CACHE}"} {
		if _, err := ExpandArgs([]string{bad}, paths); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if !ValidPickName("photo-in") || ValidPickName("NOTES") || ValidPickName("1x") || PickEnvName("photo-in") != "WARP_PICK_PHOTO_IN" {
		t.Errorf("pick name rules")
	}
}
