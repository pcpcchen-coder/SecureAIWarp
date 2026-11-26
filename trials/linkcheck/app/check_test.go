package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeTree creates files (path -> content) under a fresh temp directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// testServer serves canned responses keyed by path.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	var flaky atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/redirect-broken", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/missing", http.StatusFound)
	})
	mux.HandleFunc("/no-head", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		// Fails the first HEAD and GET, succeeds afterwards.
		if flaky.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func problemsByURL(rep *Report) map[string]Problem {
	m := map[string]Problem{}
	for _, p := range rep.Problems {
		m[p.File+":"+p.URL] = p
	}
	return m
}

func TestInternalLinks(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"README.md": "# Docs Home\n\n" +
			"[guide](guide/install.md)\n" + // 3 ok
			"[anchor](guide/install.md#step-2-設定)\n" + // 4 ok (CJK slug)
			"[bad anchor](guide/install.md#nope)\n" + // 5 broken
			"[missing](guide/missing.md)\n" + // 6 broken
			"[self](#docs-home)\n" + // 7 ok
			"[self bad](#nowhere)\n" + // 8 broken
			"[ext-less](guide/install)\n" + // 9 ok -> install.md
			"[html](guide/install.html#step-1)\n" + // 10 ok -> install.md
			"[dir](guide/)\n" + // 11 ok -> guide/index.md
			"[dir anchor](guide/#guide-index)\n" + // 12 ok
			"[image](img/logo.png)\n" + // 13 ok
			"[img anchor ignored](img/logo.png#x)\n" + // 14 ok (not markdown)
			"[mail](mailto:a@example.com)\n" + // 15 skipped
			"[case](guide/install.md#Step-1)\n" + // 16 ok (case-insensitive)
			"[encoded](my%20notes.md)\n" + // 17 ok
			"[dup](guide/install.md#faq-1)\n", // 18 ok (second FAQ heading)
		"guide/index.md":   "# Guide Index\n",
		"guide/install.md": "# Install\n\n## Step 1\n\n## Step 2: 設定\n\n## FAQ\n\n## FAQ\n\n[up](../README.md#docs-home)\n[root](/README.md)\n[root bad](/nope.md)\n",
		"img/logo.png":     "png",
		"my notes.md":      "# Notes\n",
		".hidden/x.md":     "[broken](nope.md)\n", // hidden dirs are not scanned
		"notes.txt":        "[broken](nope.md)\n", // not markdown
	})

	rep, err := Run(context.Background(), Options{Dir: dir, SkipExternal: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 4 {
		t.Errorf("Files = %d, want 4", rep.Files)
	}
	want := []Problem{
		{Occurrence{"README.md", 5, "guide/install.md#nope"}, "anchor #nope not found"},
		{Occurrence{"README.md", 6, "guide/missing.md"}, "file not found"},
		{Occurrence{"README.md", 8, "#nowhere"}, "anchor #nowhere not found"},
		{Occurrence{"guide/install.md", 13, "/nope.md"}, "file not found"},
	}
	if len(rep.Problems) != len(want) {
		t.Fatalf("got %d problems, want %d: %+v", len(rep.Problems), len(want), rep.Problems)
	}
	for i := range want {
		if rep.Problems[i] != want[i] {
			t.Errorf("problem %d = %+v, want %+v", i, rep.Problems[i], want[i])
		}
	}
	if rep.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", rep.Skipped)
	}
}

func TestExternalLinks(t *testing.T) {
	srv := testServer(t)
	u := srv.URL
	dir := writeTree(t, map[string]string{
		"a.md": strings.Join([]string{
			"[ok](" + u + "/ok)",
			"[missing](" + u + "/missing)",
			"[gone](" + u + "/gone)",
			"[redirect](" + u + "/redirect)",
			"[redirect broken](" + u + "/redirect-broken)",
			"[no head](" + u + "/no-head)",
			"[forbidden](" + u + "/forbidden)",
			"[error](" + u + "/error)",
			"[flaky](" + u + "/flaky)",
			"[with fragment](" + u + "/ok#section)",
			"[excluded](" + u + "/missing?skip=1)",
		}, "\n"),
		"b.md": "\n\nAgain " + u + "/missing here\n",
	})

	rep, err := Run(context.Background(), Options{
		Dir:          dir,
		Concurrency:  4,
		Timeout:      5 * time.Second,
		Retries:      1,
		RetryDelay:   10 * time.Millisecond,
		Exclude:      mustRegexps(t, `skip=1`),
		AcceptStatus: map[int]bool{403: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := problemsByURL(rep)
	wantBroken := map[string]string{
		"a.md:" + u + "/missing":         "HTTP 404 Not Found",
		"a.md:" + u + "/gone":            "HTTP 410 Gone",
		"a.md:" + u + "/redirect-broken": "HTTP 404 Not Found",
		"a.md:" + u + "/error":           "HTTP 500 Internal Server Error",
		"b.md:" + u + "/missing":         "HTTP 404 Not Found",
	}
	if len(got) != len(wantBroken) {
		t.Errorf("got %d problems, want %d: %+v", len(got), len(wantBroken), rep.Problems)
	}
	for k, reason := range wantBroken {
		if got[k].Reason != reason {
			t.Errorf("%s: reason %q, want %q", k, got[k].Reason, reason)
		}
	}
	if p := got["b.md:"+u+"/missing"]; p.Line != 3 {
		t.Errorf("b.md line = %d, want 3", p.Line)
	}
	// /ok and /ok#section are the same request; /missing appears in two files.
	if rep.Unique != 9 {
		t.Errorf("Unique = %d, want 9", rep.Unique)
	}
	if rep.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", rep.Skipped)
	}
}

func TestExternalTimeoutAndUnreachable(t *testing.T) {
	srv := testServer(t)
	// A listener that is closed immediately gives a "connection refused" URL.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	dir := writeTree(t, map[string]string{
		"a.md": "[slow](" + srv.URL + "/slow)\n[dead](" + deadURL + "/x)\n",
	})
	rep, err := Run(context.Background(), Options{Dir: dir, Timeout: 200 * time.Millisecond, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	got := problemsByURL(rep)
	if r := got["a.md:"+srv.URL+"/slow"].Reason; r != "request failed: timeout" {
		t.Errorf("slow reason = %q", r)
	}
	if r := got["a.md:"+deadURL+"/x"].Reason; !strings.HasPrefix(r, "request failed:") {
		t.Errorf("dead reason = %q", r)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var cur, peak atomic.Int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		mu.Lock()
		if n > peak.Load() {
			peak.Store(n)
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		cur.Add(-1)
	}))
	defer srv.Close()

	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("[x](" + srv.URL + "/p" + string(rune('a'+i)) + ")\n")
	}
	dir := writeTree(t, map[string]string{"a.md": b.String()})

	start := time.Now()
	rep, err := Run(context.Background(), Options{Dir: dir, Concurrency: 5, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if len(rep.Problems) != 0 {
		t.Fatalf("unexpected problems: %+v", rep.Problems)
	}
	if p := peak.Load(); p > 5 || p < 2 {
		t.Errorf("peak concurrency = %d, want between 2 and 5", p)
	}
	// 20 requests x 50ms sequentially would be 1s; with 5 workers ~200ms.
	if elapsed > 800*time.Millisecond {
		t.Errorf("took %v; requests do not seem to run concurrently", elapsed)
	}
}

func TestRunCLI(t *testing.T) {
	srv := testServer(t)
	dir := writeTree(t, map[string]string{
		"index.md": "# Home\n[ok](other.md)\n[bad](nope.md)\n[ext](" + srv.URL + "/missing)\n",
		"other.md": "# Other\n",
	})

	t.Run("broken links exit 1", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"-retries", "0", dir}, &out, &errb)
		if code != exitBroken {
			t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitBroken, errb.String())
		}
		want := "index.md:3: nope.md (file not found)\n" +
			"index.md:4: " + srv.URL + "/missing (HTTP 404 Not Found)\n"
		if out.String() != want {
			t.Errorf("stdout:\n%s\nwant:\n%s", out.String(), want)
		}
		if !strings.Contains(errb.String(), "2 broken") {
			t.Errorf("summary missing from stderr: %q", errb.String())
		}
	})

	t.Run("offline only checks internal links", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"-offline", dir}, &out, &errb)
		if code != exitBroken || strings.Count(out.String(), "\n") != 1 {
			t.Errorf("code=%d stdout=%q", code, out.String())
		}
	})

	t.Run("all ok exits 0", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"-exclude", `nope\.md`, "-exclude", "/missing$", "-quiet", dir}, &out, &errb)
		if code != exitOK || out.Len() != 0 || errb.Len() != 0 {
			t.Errorf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
		}
	})

	t.Run("json output", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"-format", "json", "-offline", dir}, &out, &errb)
		if code != exitBroken {
			t.Fatalf("code = %d", code)
		}
		var res struct {
			Files  int
			Broken []struct {
				File   string
				Line   int
				URL    string
				Reason string
			}
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatalf("invalid json: %v\n%s", err, out.String())
		}
		if res.Files != 2 || len(res.Broken) != 1 || res.Broken[0].Line != 3 || res.Broken[0].URL != "nope.md" {
			t.Errorf("unexpected json: %+v", res)
		}
	})

	t.Run("usage errors exit 2", func(t *testing.T) {
		for _, args := range [][]string{
			{filepath.Join(dir, "does-not-exist")},
			{"-format", "xml", dir},
			{"-exclude", "(", dir},
			{"-accept", "abc", dir},
			{dir, dir},
			{"-no-such-flag"},
		} {
			var out, errb bytes.Buffer
			if code := run(context.Background(), args, &out, &errb); code != exitUsage {
				t.Errorf("args %v: exit code = %d, want %d", args, code, exitUsage)
			}
		}
	})
}

func mustRegexps(t *testing.T, exprs ...string) []*regexp.Regexp {
	t.Helper()
	var out []*regexp.Regexp
	for _, e := range exprs {
		out = append(out, regexp.MustCompile(e))
	}
	return out
}
