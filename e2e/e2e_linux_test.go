//go:build linux

// Package e2e runs the real warp binary against the example apps: a
// well-behaved app must keep working inside the shell, and a deliberately
// malicious app must have every harmful action blocked. The tests need root
// (to build an isolated veth test network); they never touch the real
// Internet. Every app test runs twice: once with warp running as root and
// once with warp running as an ordinary, unprivileged user (root only
// builds the test network and the fixtures, then drops to that uid).
package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	upstreamIP = "1.2.3.4"
	hostIP     = "1.2.3.1"
	realKey    = "sk-real-e2e-7f3a9c1d5b2e8f40"
)

var h struct {
	repo, dir, warp, hosts, ca, upLog string
	idents                            []*who
	server                            *exec.Cmd
	loopURL, loopMarker               string
	loopHits                          atomic.Int64
	setupErr                          error
}

func TestMain(m *testing.M) {
	if os.Getenv("WARP_E2E_UPSTREAM") == "1" {
		os.Exit(runUpstream())
	}
	if os.Geteuid() != 0 {
		fmt.Println("e2e: these tests need root to build the isolated veth test network; run them with sudo")
		os.Exit(m.Run())
	}
	h.setupErr = setup()
	code := m.Run()
	if h.server != nil && h.server.Process != nil {
		h.server.Process.Kill()
		h.server.Wait()
	}
	if h.dir != "" && os.Getenv("WARP_E2E_KEEP") == "" {
		os.RemoveAll(h.dir)
	}
	os.Exit(code)
}

func need(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("需要 root 才能建立隔離的測試網路（veth）")
	}
	if h.setupErr != nil {
		t.Fatalf("e2e setup failed: %v", h.setupErr)
	}
}

// ---- setup ----

func setup() error {
	var err error
	if h.repo, err = filepath.Abs(".."); err != nil {
		return err
	}
	if h.dir, err = os.MkdirTemp("", "warp-e2e-"); err != nil {
		return err
	}
	h.warp = filepath.Join(h.dir, "warp")
	build := exec.Command("go", "build", "-o", h.warp, "./cmd/warp")
	build.Dir = h.repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build warp: %v\n%s", err, out)
	}
	// The binary and the shared fixtures must be usable by the
	// unprivileged identity.
	if err := os.Chmod(h.dir, 0o755); err != nil {
		return err
	}
	if h.idents, err = makeIdentities(); err != nil {
		return err
	}
	h.upLog = filepath.Join(h.dir, "upstream.log")
	certFile, keyFile, err := makeCerts()
	if err != nil {
		return err
	}
	// Upstream server in its own network namespace.
	h.server = exec.Command(os.Args[0])
	h.server.Env = append(os.Environ(), "WARP_E2E_UPSTREAM=1", "WARP_E2E_CERT="+certFile, "WARP_E2E_KEY="+keyFile, "WARP_E2E_LOG="+h.upLog)
	h.server.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	h.server.Stderr = os.Stderr
	out, err := h.server.StdoutPipe()
	if err != nil {
		return err
	}
	if err := h.server.Start(); err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}
	if err := createVeth("wv0", "wv1", h.server.Process.Pid); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}
	if err := configureIface("wv0", net.ParseIP(hostIP)); err != nil {
		return err
	}
	ready := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if sc.Text() == "READY" {
				ready <- nil
				io.Copy(io.Discard, out)
				return
			}
		}
		ready <- fmt.Errorf("upstream exited before READY")
	}()
	select {
	case err := <-ready:
		if err != nil {
			return err
		}
	case <-time.After(15 * time.Second):
		return fmt.Errorf("upstream not ready")
	}
	// A service on the host's loopback that must stay unreachable.
	h.loopMarker = "host-loopback-secret-" + fmt.Sprint(time.Now().UnixNano())
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.loopHits.Add(1)
		fmt.Fprint(w, h.loopMarker)
	}))
	h.loopURL = fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)
	// Operator-side name overrides for the gate (never visible to apps).
	h.hosts = filepath.Join(h.dir, "hosts")
	return os.WriteFile(h.hosts, []byte(fmt.Sprintf(
		"%s api.notes.example evil.example cdn.notes.example\n127.0.0.1 status.notes.example\n10.0.0.5 lan.notes.example\n", upstreamIP)), 0o644)
}

func makeCerts() (string, string, error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e upstream CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	ca, _ := x509.ParseCertificate(caDER)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "api.notes.example"},
		DNSNames:  []string{"api.notes.example", "evil.example", "status.notes.example", "cdn.notes.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, lt, ca, &k.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	h.ca = filepath.Join(h.dir, "upstream-ca.pem")
	os.WriteFile(h.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	cf := filepath.Join(h.dir, "upstream.crt")
	kf := filepath.Join(h.dir, "upstream.key")
	os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	kb, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cf, kf, nil
}

// ---- upstream server (runs in its own network namespace) ----

type logEntry struct {
	Host    string              `json:"host"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	TLS     bool                `json:"tls"`
}

func runUpstream() int {
	if err := waitIface("wv1", 10*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := configureIface("lo", nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := configureIface("wv1", net.ParseIP(upstreamIP)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var mu sync.Mutex
	logf, err := os.OpenFile(os.Getenv("WARP_E2E_LOG"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 1
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		e := logEntry{Host: r.Host, Method: r.Method, Path: r.URL.Path, Headers: r.Header, Body: string(body), TLS: r.TLS != nil}
		b, _ := json.Marshal(e)
		mu.Lock()
		logf.Write(append(b, '\n'))
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/summarize":
			k := r.Header.Get("x-api-key")
			if k != realKey && !strings.HasPrefix(k, "warp-decoy-") {
				http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("content-type", "application/json")
			fmt.Fprint(w, `{"ok":true,"summary":"2 notes"}`)
		case "/echo-headers":
			json.NewEncoder(w).Encode(r.Header)
		case "/ping":
			fmt.Fprint(w, "pong")
		default:
			fmt.Fprint(w, "ok")
		}
	})
	cert, err := tls.LoadX509KeyPair(os.Getenv("WARP_E2E_CERT"), os.Getenv("WARP_E2E_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	l443, err := tls.Listen("tcp", upstreamIP+":443", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	l80, err := net.Listen("tcp", upstreamIP+":80")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	go http.Serve(l80, handler)
	fmt.Println("READY")
	http.Serve(l443, handler)
	return 0
}

func upstreamEntries(t *testing.T) []logEntry {
	t.Helper()
	b, _ := os.ReadFile(h.upLog)
	var out []logEntry
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e logEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("bad upstream log line: %s", line)
		}
		out = append(out, e)
	}
	return out
}

// ---- helpers ----

type result struct {
	stdout, stderr string
	code           int
}

// who is the OS identity warp runs as in one subtest.
type who struct {
	name     string
	uid, gid int
	state    string // WARP_STATE_DIR
	home     string // HOME
}

func (w *who) root() bool { return w.uid == 0 }

// defaultUnprivUID is the uid used for the unprivileged runs. It needs no
// passwd entry: warp maps exactly this uid into its user namespace.
const defaultUnprivUID = 47613

func makeIdentities() ([]*who, error) {
	want := os.Getenv("WARP_E2E_IDENTITIES")
	if want == "" {
		want = "root,user"
	}
	uid := defaultUnprivUID
	if v := os.Getenv("WARP_E2E_UID"); v != "" {
		fmt.Sscan(v, &uid)
	}
	var out []*who
	for _, n := range strings.Split(want, ",") {
		w := &who{name: n}
		switch n {
		case "root":
		case "user":
			w.uid, w.gid = uid, uid
		default:
			return nil, fmt.Errorf("unknown identity %q in WARP_E2E_IDENTITIES", n)
		}
		w.state = filepath.Join(h.dir, "state-"+n)
		w.home = filepath.Join(h.dir, "home-"+n)
		for _, d := range []string{w.state, w.home} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return nil, err
			}
			if err := os.Chown(d, w.uid, w.gid); err != nil {
				return nil, err
			}
		}
		out = append(out, w)
	}
	return out, nil
}

// forEachIdentity runs fn once per configured identity.
func forEachIdentity(t *testing.T, fn func(t *testing.T, w *who)) {
	need(t)
	for _, w := range h.idents {
		w := w
		t.Run(w.name, func(t *testing.T) { fn(t, w) })
	}
}

// newBase returns an empty directory for one test case under the shared,
// traversable test directory.
func newBase(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(h.dir, "case-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)
	if os.Getenv("WARP_E2E_KEEP") == "" {
		t.Cleanup(func() { os.RemoveAll(d) })
	}
	return d
}

// own hands every file under the given paths to w, so that for the
// unprivileged identity only the shell (not file permissions) stands
// between the app and those files.
func (w *who) own(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		err := filepath.Walk(p, func(q string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(q, w.uid, w.gid)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// mustOwn asserts that every path is owned by w and accessible to its owner.
func (w *who) mustOwn(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		sys := st.Sys().(*syscall.Stat_t)
		if int(sys.Uid) != w.uid {
			t.Fatalf("%s is owned by uid %d, want %d", p, sys.Uid, w.uid)
		}
		if st.Mode().Perm()&0o600 != 0o600 {
			t.Fatalf("%s is not readable and writable by its owner (%v)", p, st.Mode())
		}
	}
}

func warpEnv(w *who, extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + w.home,
		"WARP_STATE_DIR=" + w.state, "WARP_HOSTS_FILE=" + h.hosts, "SSL_CERT_FILE=" + h.ca,
	}
	return append(env, extra...)
}

func (w *who) command(env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(h.warp, args...)
	cmd.Env = env
	cmd.Dir = w.home
	if !w.root() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(w.uid), Gid: uint32(w.gid), Groups: []uint32{}}}
	}
	return cmd
}

func runWarp(t *testing.T, w *who, env []string, args ...string) result {
	t.Helper()
	cmd := w.command(env, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run warp %v: %v", args, err)
	}
	t.Logf("$ warp %s\n[exit %d]\n--- stdout ---\n%s--- stderr ---\n%s", strings.Join(args, " "), code, so.String(), se.String())
	return result{so.String(), se.String(), code}
}

var urlRe = regexp.MustCompile(`http://127\.0\.0\.1:\d+/\?warp_token=[0-9a-f]+`)

// runWarpServing starts warp, waits for the ingress URL on stderr, calls fn
// with it and then waits for warp to exit.
func runWarpServing(t *testing.T, w *who, env []string, fn func(url string), args ...string) result {
	t.Helper()
	cmd := w.command(env, args...)
	var so bytes.Buffer
	cmd.Stdout = &so
	pr, pw := io.Pipe()
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var se bytes.Buffer
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			se.WriteString(line + "\n")
			if m := urlRe.FindString(line); m != "" {
				select {
				case found <- m:
				default:
				}
			}
		}
	}()
	select {
	case u := <-found:
		fn(u)
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("no ingress URL printed; stderr:\n%s", se.String())
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		err = <-done
	}
	pw.Close()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	time.Sleep(50 * time.Millisecond)
	t.Logf("$ warp %s\n[exit %d]\n--- stdout ---\n%s--- stderr ---\n%s", strings.Join(args, " "), code, so.String(), se.String())
	return result{so.String(), se.String(), code}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if strings.HasPrefix(rel, ".warp") || strings.Contains(rel, "__pycache__") {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func fillPurposes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "（待填寫：用一句人話說明用途）", "端對端測試用途")
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s: expected to contain %q", what, sub)
		}
	}
}

// appStateDir is the core's per-app state directory (see internal/state):
// keyed by the app name and the canonical app root.
func appStateDir(t *testing.T, w *who, app string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(app)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(w.state, "apps", filepath.Base(app)+"-"+hex.EncodeToString(sum[:6]))
}

func ledgerPath(t *testing.T, w *who, app string) string {
	t.Helper()
	p := filepath.Join(appStateDir(t, w, app), "ledger.jsonl")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("ledger for %s: %v", app, err)
	}
	return p
}

func ledgerEntries(t *testing.T, w *who, app string) []map[string]any {
	t.Helper()
	b, _ := os.ReadFile(ledgerPath(t, w, app))
	var out []map[string]any
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e map[string]any
		json.Unmarshal(line, &e)
		out = append(out, e)
	}
	return out
}

func httpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 15 * time.Second}
}
