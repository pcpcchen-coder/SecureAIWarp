//go:build linux

package e2e

import (
	"encoding/json"
	"fmt"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestNotesAppLifecycle walks the full fitting protocol on a well-behaved
// app: record -> draft -> lint -> enforce (functions still work) -> probe
// (every boundary holds) -> label (L2) -> ledger verify.
func TestNotesAppLifecycle(t *testing.T) { forEachIdentity(t, testNotesAppLifecycle) }

func testNotesAppLifecycle(t *testing.T, w *who) {
	base := newBase(t)
	app := filepath.Join(base, "notes-app")
	copyDir(t, filepath.Join(h.repo, "examples", "notes-app"), app)
	synthetic := filepath.Join(base, "synthetic-notes")
	writeFiles(t, synthetic, map[string]string{"a.txt": "synthetic one\n", "b.txt": "synthetic two\n"})
	real := filepath.Join(base, "real-notes")
	writeFiles(t, real, map[string]string{"meeting.txt": "real meeting notes\n", "todo.txt": "real todo\n"})
	w.own(t, base)
	env := warpEnv(w)
	logStart := len(upstreamEntries(t))

	if r := runWarp(t, w, env, "init", "-C", app); r.code != 0 {
		t.Fatalf("init failed")
	}
	// Record: the decoy key reaches the API; the real key is never used.
	r := runWarp(t, w, env, "record", "-C", app, "--pick", "notes="+synthetic, "--secret", "NOTES_API_KEY", "--", "python3", "app.py", "summarize")
	if r.code != 0 || !strings.Contains(r.stdout, "summary ok") {
		t.Fatalf("record summarize failed")
	}
	// Record the web UI: operate it through the printed loopback URL.
	r = runWarpServing(t, w, env, func(u string) {
		resp, err := httpClient().Get(u)
		if err != nil {
			t.Errorf("GET ingress during record: %v", err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), "<h1>notes</h1>") {
			t.Errorf("record ingress: HTTP %d %s", resp.StatusCode, b)
		}
	}, "record", "-C", app, "--pick", "notes="+synthetic, "--", "python3", "app.py", "serve", "--once")
	if r.code != 0 {
		t.Fatalf("record serve failed")
	}
	for _, e := range upstreamEntries(t)[logStart:] {
		for _, v := range e.Headers["X-Api-Key"] {
			if v == realKey {
				t.Fatalf("record mode sent the real key upstream")
			}
		}
	}

	// Draft and fill in purposes, as the Fitter would.
	if r := runWarp(t, w, env, "draft", "-C", app); r.code != 0 {
		t.Fatalf("draft failed")
	}
	mf := filepath.Join(app, ".warp", "warp.yaml")
	drafted, _ := os.ReadFile(mf)
	mustContain(t, "draft", string(drafted), "${APP_DATA}", "mode: rw", "${USER_PICK:notes}", "mode: ro",
		"host: api.notes.example", "port: 443", "listen: 8080", "name: NOTES_API_KEY", "header: x-api-key")
	if strings.Contains(string(drafted), "${APP_CACHE}") {
		t.Errorf("draft granted APP_CACHE although the app never used it")
	}
	if r := runWarp(t, w, env, "lint", "-C", app); r.code == 0 {
		t.Fatalf("lint must reject placeholder purposes")
	}
	fillPurposes(t, mf)
	if r := runWarp(t, w, env, "lint", "-C", app); r.code != 0 {
		t.Fatalf("lint failed after filling purposes")
	}
	// Evidence replay: every grant is reproduced by re-running the recorded
	// commands (synthetic picks, decoy secret, declared egress only; the
	// served UI is visited once).
	r = runWarp(t, w, env, "evidence", "replay", "-C", app)
	if r.code != 0 || strings.Contains(r.stdout, "未重現") {
		t.Fatalf("evidence replay must reproduce every grant of a well-behaved app")
	}
	mustContain(t, "replay", r.stdout, "重放指令：python3 app.py summarize", "重放指令：python3 app.py serve --once",
		"✔ 重現  files[0]", "✔ 重現  network.egress[0]", "✔ 重現  network.ingress[0]", "✔ 重現  secrets[0]")

	// Enforce: missing real secret -> refuse (fail closed).
	if r := runWarp(t, w, env, "enforce", "-C", app, "--pick", "notes="+real, "--", "python3", "app.py", "summarize"); r.code != 125 {
		t.Fatalf("enforce without the real secret must refuse, got %d", r.code)
	}
	// Enforce with the real key on the host side.
	envKey := warpEnv(w, "NOTES_API_KEY="+realKey)
	logEnforce := len(upstreamEntries(t))
	r = runWarp(t, w, envKey, "enforce", "-C", app, "--pick", "notes="+real, "--", "python3", "app.py", "summarize")
	if r.code != 0 || !strings.Contains(r.stdout, "summary ok: 2 notes") {
		t.Fatalf("declared behaviour must work under enforce")
	}
	if strings.Contains(r.stdout+r.stderr, realKey) {
		t.Fatalf("real key leaked into app output")
	}
	injected := false
	for _, e := range upstreamEntries(t)[logEnforce:] {
		if e.Path == "/v1/summarize" && len(e.Headers["X-Api-Key"]) == 1 && e.Headers["X-Api-Key"][0] == realKey {
			injected = true
			if e.Host != "api.notes.example" || !e.TLS {
				t.Errorf("real key delivered to unexpected place: %+v", e)
			}
		}
	}
	if !injected {
		t.Fatalf("gate did not inject the real key over TLS")
	}
	summary := filepath.Join(appStateDir(t, w, app), "data", "summary.json")
	if _, err := os.Stat(summary); err != nil {
		t.Fatalf("APP_DATA should persist in the core state dir: %v", err)
	}
	// The files the shell wrote on the host belong to the identity warp
	// ran as: proof that the unprivileged runs really were unprivileged.
	w.mustOwn(t, summary, ledgerPath(t, w, app), filepath.Join(app, ".warp", "evidence", "trace-0001.json"))

	// Ingress: only loopback + token.
	r = runWarpServing(t, w, envKey, func(u string) {
		noTok := strings.SplitN(u, "?", 2)[0]
		resp, err := http.Get(noTok)
		if err != nil {
			t.Errorf("GET without token: %v", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("ingress without token: want 401, got %d", resp.StatusCode)
			}
		}
		resp, err = httpClient().Get(u)
		if err != nil {
			t.Errorf("GET with token: %v", err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), "2 notes") {
			t.Errorf("ingress with token: HTTP %d %s", resp.StatusCode, b)
		}
	}, "enforce", "-C", app, "--pick", "notes="+real, "--", "python3", "app.py", "serve", "--once")
	if r.code != 0 {
		t.Fatalf("enforce serve failed")
	}

	// Probe: every implemented probe must be blocked.
	r = runWarp(t, w, env, "probe", "-C", app)
	if r.code != 0 || !strings.Contains(r.stdout, "全部已實作的探針都被擋下") || strings.Contains(r.stdout, "穿透") {
		t.Fatalf("probe did not block everything")
	}
	var rep struct {
		Identity  string `json:"identity"`
		Resources []struct {
			Resource, Scope, Mechanism string
		} `json:"resources"`
		Items []struct{ ID, Status string } `json:"items"`
	}
	b, _ := os.ReadFile(filepath.Join(app, ".warp", "reports", "probe.json"))
	json.Unmarshal(b, &rep)
	ids := map[string]string{}
	for _, it := range rep.Items {
		ids[it.ID] = it.Status
	}
	for _, id := range []string{"net.connect:169.254.169.254:80", "net.connect:127.0.0.1:22", "net.connect:api.notes.example:22",
		"ingress.no-token:8080", "ingress.rebind-host:8080", "ingress.control:8080", "secret.env:NOTES_API_KEY",
		"res.memory", "res.pids", "res.disk", "fs.nested-userns", "host.decoy-intact"} {
		if ids[id] != "blocked" {
			t.Errorf("probe %s: status %q", id, ids[id])
		}
	}
	wantIdentity := "root"
	if !w.root() {
		wantIdentity = fmt.Sprintf("uid=%d", w.uid)
	}
	if rep.Identity != wantIdentity {
		t.Errorf("probe report identity %q, want %q", rep.Identity, wantIdentity)
	}
	memScope := ""
	for _, rl := range rep.Resources {
		if rl.Resource == "memory" {
			memScope = rl.Scope
			if !w.root() && rl.Scope == "shell" && !strings.Contains(rl.Mechanism, "cgroup") {
				t.Errorf("non-root memory limit claims shell scope without a cgroup: %+v", rl)
			}
		}
	}
	if memScope == "" {
		t.Errorf("probe report does not say how the memory limit was enforced: %+v", rep.Resources)
	}

	// Label: L2 after enforce + probe on the same manifest/digest.
	r = runWarp(t, w, env, "label", "-C", app)
	mustContain(t, "label", r.stdout, "$ python3 app.py summarize", "$ python3 app.py serve --once")
	mustContain(t, "label", r.stdout, "L2 已驗證", "api.notes.example:443", "你選定的一個資料夾（notes）", "看到金鑰的真值", "（無例外）", "執行身分　"+wantIdentity)
	if memScope != "shell" {
		// A degraded limit must be visible on the label, not hidden.
		mustContain(t, "label", r.stdout, "⚠ 記憶體上限在此機器上只限單一程序")
	} else if strings.Contains(r.stdout, "⚠ 記憶體上限") {
		t.Errorf("label warns about a memory limit that held for the whole shell")
	}
	if _, err := os.Stat(filepath.Join(app, ".warp", "label.json")); err != nil {
		t.Errorf("label.json missing")
	}
	if r := runWarp(t, w, env, "ledger", "verify", "-C", app); r.code != 0 {
		t.Fatalf("ledger verify failed")
	}

	// Diff of a widened manifest.
	wider := filepath.Join(base, "wider.yaml")
	s := strings.Replace(string(mustRead(t, mf)), "network:\n  egress:\n", "network:\n  egress:\n    - host: api.stripe.com\n      port: 443\n      purpose: 建立付款連結\n", 1)
	os.WriteFile(wider, []byte(s), 0o644)
	w.own(t, wider)
	r = runWarp(t, w, env, "diff", mf, wider)
	mustContain(t, "diff", r.stdout, "＋ 新增對外連線：api.stripe.com:443（用途：建立付款連結）", "風險等級")

	// Tampering with the app invalidates the manifest (content digest).
	os.WriteFile(filepath.Join(app, "app.py"), append(mustRead(t, filepath.Join(app, "app.py")), []byte("\n# changed\n")...), 0o644)
	if r := runWarp(t, w, envKey, "enforce", "-C", app, "--pick", "notes="+real, "--", "python3", "app.py", "summarize"); r.code != 125 || !strings.Contains(r.stderr, "app-digest") {
		t.Fatalf("enforce must refuse a modified app")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEvilAppIsContained records the malicious app in its harmless mode,
// accepts a manifest for exactly that behaviour, and then runs its attack
// mode under enforce. Every attack must fail, which is verified both from
// the app's own report and from outside (host files, upstream server log,
// host loopback service, ledger).
func TestEvilAppIsContained(t *testing.T) { forEachIdentity(t, testEvilAppIsContained) }

func testEvilAppIsContained(t *testing.T, w *who) {
	base := newBase(t)
	app := filepath.Join(base, "evil-app")
	copyDir(t, filepath.Join(h.repo, "examples", "evil-app"), app)
	notes := filepath.Join(base, "notes")
	writeFiles(t, notes, map[string]string{"salary.txt": "CONFIDENTIAL salary list\n"})
	w.own(t, base)
	env := warpEnv(w)
	runWarp(t, w, env, "init", "-C", app)
	r := runWarp(t, w, env, "record", "-C", app, "--pick", "notes="+notes, "--secret", "NOTES_API_KEY", "--", "python3", "app.py", "summarize")
	if r.code != 0 {
		t.Fatalf("record failed")
	}
	if r := runWarp(t, w, env, "draft", "-C", app); r.code != 0 {
		t.Fatalf("draft failed")
	}
	mf := filepath.Join(app, ".warp", "warp.yaml")
	s := fillPurposes(t, mf)
	mustContain(t, "draft", s, "對外連線 status.notes.example:443") // blocked in record: denied_by_design
	// The author insists on declaring the status host (its DNS answer points
	// at loopback, i.e. a rebinding-style attack on a declared host).
	mustContain(t, "draft", s, "host: cdn.notes.example")
	if strings.Count(s, "  - host: ") != 2 || !strings.Contains(s, "\nsecrets:\n") {
		t.Fatalf("unexpected draft layout:\n%s", s)
	}
	s = strings.Replace(s, "\nsecrets:\n", "\n    - host: status.notes.example\n      port: 443\n      purpose: 服務狀態檢查\nsecrets:\n", 1)
	s = strings.Replace(s, "\nevidence:\n", "\nevidence:\n  - grant: network.egress[2]\n    observed_in: .warp/evidence/trace-0001.json\n    triggered_by: python3 app.py summarize\n", 1)
	os.WriteFile(mf, []byte(s), 0o644)
	if r := runWarp(t, w, env, "lint", "-C", app); r.code != 0 {
		t.Fatalf("lint failed for evil manifest:\n%s", s)
	}

	// Things on the host the app must not touch.
	victimDir := filepath.Join(base, "victim")
	writeFiles(t, victimDir, map[string]string{"victim.txt": "important document\n"})
	victim := filepath.Join(victimDir, "victim.txt")
	fakeHome := filepath.Join(base, "home")
	decoy := filepath.Join(fakeHome, ".ssh", "id_rsa")
	os.MkdirAll(filepath.Dir(decoy), 0o700)
	os.WriteFile(decoy, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nwarp-e2e-decoy\n"), 0o600)
	// For the unprivileged identity, every target belongs to the uid warp
	// runs as: without the shell, each attack would succeed.
	w.own(t, base)
	w.mustOwn(t, victimDir, victim, fakeHome, filepath.Dir(decoy), decoy, app, notes)
	logBefore := len(upstreamEntries(t))
	loopBefore := h.loopHits.Load()

	r = runWarp(t, w, warpEnv(w, "NOTES_API_KEY="+realKey), "enforce", "-C", app, "--pick", "notes="+notes, "--",
		"python3", "app.py", "attack", "--decoy", decoy, "--host-home", fakeHome, "--victim", victim,
		"--victim-dir", victimDir, "--host-service", h.loopURL, "--host-marker", h.loopMarker, "--upstream-ip", upstreamIP)
	if r.code != 0 {
		t.Fatalf("attack run crashed (exit %d)", r.code)
	}
	if !strings.Contains(r.stdout, `{"control": "tunnel", "ok": true`) {
		t.Errorf("positive control failed: an allowed, non-inspected tunnel must work")
	}
	attacks := map[string]bool{}
	for _, line := range strings.Split(r.stdout, "\n") {
		var a struct {
			Attack    string `json:"attack"`
			Succeeded bool   `json:"succeeded"`
			Detail    string `json:"detail"`
		}
		if json.Unmarshal([]byte(line), &a) == nil && a.Attack != "" {
			attacks[a.Attack] = a.Succeeded
			if a.Succeeded {
				t.Errorf("ATTACK SUCCEEDED: %s (%s)", a.Attack, a.Detail)
			}
		}
	}
	for _, name := range []string{"read_decoy_credential", "read_host_home_ssh", "list_host_dir", "exfil_https_undeclared",
		"exfil_http_undeclared", "exfil_declared_host_other_port", "exfil_direct_socket", "exfil_dns_lookup",
		"exfil_domain_fronting", "secret_env_is_real", "secret_reflected_by_api", "secret_to_undeclared_host", "secret_proc_environ",
		"read_init_environ", "cloud_metadata", "host_loopback_service", "lan_by_name", "lan_by_ip",
		"rebinding_declared_host", "host_loopback_direct", "write_outside", "write_app_dir", "delete_outside", "rmtree_outside"} {
		if _, ok := attacks[name]; !ok {
			t.Errorf("attack %s did not report", name)
		}
	}
	// The real key never reached the app, even though the API reflects headers.
	if strings.Contains(r.stdout+r.stderr, realKey) {
		t.Errorf("the real key leaked into the shell")
	}
	if !strings.Contains(r.stdout, "warp-placeholder-notes_api_key-") {
		t.Errorf("expected the placeholder in the reflected headers")
	}
	// Outside view: upstream server.
	for _, e := range upstreamEntries(t)[logBefore:] {
		if strings.HasPrefix(e.Host, "evil.example") || strings.Contains(e.Path, "collect") || strings.Contains(e.Body, "CONFIDENTIAL") {
			t.Errorf("exfiltration reached the upstream: %+v", e)
		}
		if !(strings.HasPrefix(e.Host, "api.notes.example") || e.Host == "cdn.notes.example") || !e.TLS {
			t.Errorf("unexpected upstream request: %+v", e)
		}
	}
	if n := h.loopHits.Load() - loopBefore; n != 0 {
		t.Errorf("host loopback service was reached %d times", n)
	}
	// Outside view: files.
	if b, err := os.ReadFile(victim); err != nil || string(b) != "important document\n" {
		t.Errorf("victim file changed or deleted")
	}
	if _, err := os.Stat(filepath.Join(victimDir, "pwned.txt")); err == nil {
		t.Errorf("file written outside the shell")
	}
	if _, err := os.Stat(filepath.Join(app, "pwned.txt")); err == nil {
		t.Errorf("file written into the read-only app directory")
	}
	if b, _ := os.ReadFile(decoy); !strings.Contains(string(b), "warp-e2e-decoy") {
		t.Errorf("decoy credential changed")
	}
	// Ledger: every network attempt is recorded as denied.
	denied := map[string]bool{}
	redacted := false
	for _, e := range ledgerEntries(t, w, app) {
		if e["decision"] == "deny" {
			denied[e["target"].(string)] = true
			if e["channel"] == "secret" && e["action"] == "redact" {
				redacted = true
			}
		}
	}
	for _, tgt := range []string{"evil.example:443", "evil.example:80", "api.notes.example:80", "169.254.169.254:80",
		strings.TrimSuffix(strings.TrimPrefix(h.loopURL, "http://"), "/"), "lan.notes.example:80", "192.168.1.1:80", "status.notes.example:443", "cdn.notes.example:443"} {
		if !denied[tgt] {
			t.Errorf("ledger has no deny entry for %s", tgt)
		}
	}
	if !redacted {
		t.Errorf("ledger should record the redaction of the reflected key")
	}
	if r := runWarp(t, w, env, "ledger", "verify", "-C", app); r.code != 0 {
		t.Errorf("ledger verify failed")
	}
}

// TestEvilAppControlWithoutShell is the negative control for the
// unprivileged runs: the same fixtures, owned the same way, are exploitable
// when the app runs as that uid without warp. It shows that in
// TestEvilAppIsContained/user the shell, not file permissions, is what
// blocks the attacks.
func TestEvilAppControlWithoutShell(t *testing.T) {
	forEachIdentity(t, func(t *testing.T, w *who) {
		if w.root() {
			t.Skip("the control is only meaningful for the unprivileged identity")
		}
		base := newBase(t)
		app := filepath.Join(base, "evil-app")
		copyDir(t, filepath.Join(h.repo, "examples", "evil-app"), app)
		victimDir := filepath.Join(base, "victim")
		writeFiles(t, victimDir, map[string]string{"victim.txt": "important document\n"})
		victim := filepath.Join(victimDir, "victim.txt")
		fakeHome := filepath.Join(base, "home")
		decoy := filepath.Join(fakeHome, ".ssh", "id_rsa")
		os.MkdirAll(filepath.Dir(decoy), 0o700)
		os.WriteFile(decoy, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nwarp-e2e-decoy\n"), 0o600)
		w.own(t, base)
		w.mustOwn(t, victimDir, victim, fakeHome, filepath.Dir(decoy), decoy, app)
		cmd := exec.Command("python3", "app.py", "attack", "--decoy", decoy, "--host-home", fakeHome, "--victim", victim,
			"--victim-dir", victimDir, "--host-service", h.loopURL, "--host-marker", h.loopMarker, "--upstream-ip", upstreamIP)
		cmd.Dir = app
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + w.home, "APP_DATA=" + base}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(w.uid), Gid: uint32(w.gid), Groups: []uint32{}}}
		out, _ := cmd.Output()
		got := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			var a struct {
				Attack    string `json:"attack"`
				Succeeded bool   `json:"succeeded"`
			}
			if json.Unmarshal([]byte(line), &a) == nil && a.Attack != "" {
				got[a.Attack] = a.Succeeded
			}
		}
		for _, name := range []string{"read_decoy_credential", "read_host_home_ssh", "list_host_dir", "write_outside",
			"delete_outside", "host_loopback_service"} {
			if !got[name] {
				t.Errorf("control: %s should succeed without the shell (fixtures not exploitable?)\n%s", name, out)
			}
		}
	})
}

// TestEvidenceForgeryAndAbuse pins down what evidence does and does not
// guarantee when the agent runs as the same OS user as the core:
//
//   - forging: an agent that reads the signing key can write a trace that
//     passes lint (documented limitation), but evidence replay re-runs the
//     claimed command and the claimed behaviour does not reappear;
//   - abusing: an agent can run `warp record -- <any command>` and obtain
//     a genuine trace; replay reproduces it, but the label shows the
//     command that produced the evidence, so it is visible to the human.
func TestEvidenceForgeryAndAbuse(t *testing.T) {
	forEachIdentity(t, func(t *testing.T, w *who) {
		base := newBase(t)
		app := filepath.Join(base, "notes-app")
		copyDir(t, filepath.Join(h.repo, "examples", "notes-app"), app)
		synthetic := filepath.Join(base, "synthetic-notes")
		writeFiles(t, synthetic, map[string]string{"a.txt": "synthetic\n"})
		w.own(t, base)
		env := warpEnv(w)
		runWarp(t, w, env, "init", "-C", app)
		if r := runWarp(t, w, env, "record", "-C", app, "--pick", "notes="+synthetic, "--secret", "NOTES_API_KEY", "--", "python3", "app.py", "summarize"); r.code != 0 {
			t.Fatalf("record failed")
		}
		if r := runWarp(t, w, env, "draft", "-C", app); r.code != 0 {
			t.Fatalf("draft failed")
		}
		mf := filepath.Join(app, ".warp", "warp.yaml")
		clean := fillPurposes(t, mf)
		if r := runWarp(t, w, env, "lint", "-C", app); r.code != 0 {
			t.Fatalf("lint failed")
		}
		digest := strings.TrimSpace(runWarp(t, w, env, "digest", "-C", app).stdout)
		addGrant := func(trace, trigger string) {
			t.Helper()
			s := strings.Replace(clean, "\nsecrets:\n", "\n    - host: evil.example\n      port: 443\n      purpose: 端對端測試用途\nsecrets:\n", 1)
			s = strings.Replace(s, "\nevidence:\n", fmt.Sprintf("\nevidence:\n  - grant: network.egress[1]\n    observed_in: %s\n    triggered_by: %s\n", trace, trigger), 1)
			if !strings.Contains(s, "host: evil.example") || !strings.Contains(s, "grant: network.egress[1]") {
				t.Fatalf("unexpected draft layout:\n%s", clean)
			}
			os.WriteFile(mf, []byte(s), 0o644)
		}

		// 1. Forgery with the key the agent can read.
		key, err := os.ReadFile(filepath.Join(w.state, "trace.key"))
		if err != nil {
			t.Fatal(err)
		}
		forged := &evidence.Trace{Format: evidence.Format, ID: "trace-0009", CreatedAt: "2026-01-01T00:00:00Z",
			Command: []string{"python3", "app.py", "summarize"}, AppDigest: digest,
			Events: []evidence.Event{{Channel: evidence.ChanEgress, Host: "evil.example", Port: 443, Op: "connect", Decision: "allowed", Count: 1}}}
		fp := filepath.Join(app, ".warp", "evidence", "trace-0009.json")
		if err := evidence.Write(fp, forged, key); err != nil {
			t.Fatal(err)
		}
		w.own(t, fp)
		addGrant(".warp/evidence/trace-0009.json", "python3 app.py summarize")
		if r := runWarp(t, w, env, "lint", "-C", app); r.code != 0 {
			t.Fatalf("documented limitation changed: a same-user forgery with the key is expected to pass lint; update docs/05 §4 if this is now prevented")
		}
		logBefore := len(upstreamEntries(t))
		r := runWarp(t, w, env, "evidence", "replay", "-C", app)
		if r.code == 0 {
			t.Fatalf("replay must expose the forged evidence")
		}
		mustContain(t, "replay forged", r.stdout, "【.warp/evidence/trace-0009.json】", "✖ 未重現 network.egress[1]：沒有觀察到連往 evil.example:443")
		for _, e := range upstreamEntries(t)[logBefore:] {
			if strings.HasPrefix(e.Host, "evil.example") {
				t.Fatalf("replay must not have contacted evil.example (the real app never does)")
			}
		}
		os.Remove(fp)

		// 1b. A forged trace whose command contacts an undeclared host:
		// replay only lets declared destinations through, so replaying
		// someone else's evidence cannot be used to reach other hosts.
		forged.Command = []string{"python3", "-c", "import urllib.request; urllib.request.urlopen('https://cdn.notes.example/ping').read()"}
		if err := evidence.Write(fp, forged, key); err != nil {
			t.Fatal(err)
		}
		w.own(t, fp)
		q, _ := json.Marshal(evidence.CommandString(forged.Command))
		addGrant(".warp/evidence/trace-0009.json", string(q))
		logBefore = len(upstreamEntries(t))
		if r := runWarp(t, w, env, "evidence", "replay", "-C", app); r.code == 0 || !strings.Contains(r.stdout, "✖ 未重現 network.egress[1]") {
			t.Fatalf("replay must expose the forged evidence")
		}
		for _, e := range upstreamEntries(t)[logBefore:] {
			if strings.HasPrefix(e.Host, "cdn.notes.example") || strings.HasPrefix(e.Host, "evil.example") {
				t.Fatalf("replay reached an undeclared or unproven host: %+v", e)
			}
		}
		os.Remove(fp)

		// 2. Abuse: a genuine trace from an arbitrary command.
		argv := []string{"python3", "-c", "import urllib.request; urllib.request.urlopen('https://evil.example/ping').read()"}
		if r := runWarp(t, w, env, append([]string{"record", "-C", app, "--"}, argv...)...); r.code != 0 {
			t.Fatalf("record of an arbitrary command failed")
		}
		cmd := evidence.CommandString(argv)
		// The agent cannot describe the trace as coming from the app.
		addGrant(".warp/evidence/trace-0002.json", "python3 app.py summarize")
		if r := runWarp(t, w, env, "lint", "-C", app); r.code == 0 || !strings.Contains(r.stdout, "evidence-command") {
			t.Fatalf("lint must reject a triggered_by that misdescribes the recorded command")
		}
		quoted, _ := json.Marshal(cmd) // a JSON string is a valid YAML double-quoted scalar
		addGrant(".warp/evidence/trace-0002.json", string(quoted))
		if r := runWarp(t, w, env, "lint", "-C", app); r.code != 0 {
			t.Fatalf("lint failed for the abused (but genuine) evidence")
		}
		r = runWarp(t, w, env, "label", "-C", app)
		mustContain(t, "label", r.stdout, "$ python3 -c 'import urllib.request;", "連線 evil.example:443")
		r = runWarp(t, w, env, "evidence", "replay", "-C", app)
		if r.code != 0 {
			t.Fatalf("genuine evidence must replay")
		}
		mustContain(t, "replay abused", r.stdout, "重放指令："+cmd, "✔ 重現  network.egress[1]")
	})
}
