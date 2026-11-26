package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
)

func TestReplacingReaderAcrossBoundaries(t *testing.T) {
	secret := "sk-REAL-0123456789"
	in := strings.Repeat("a", 100) + secret + "b" + secret + strings.Repeat("c", 7) + "sk-REAL-01"
	for _, r := range []io.Reader{strings.NewReader(in), iotest.OneByteReader(strings.NewReader(in)), iotest.HalfReader(strings.NewReader(in))} {
		n := 0
		out, err := io.ReadAll(newReplacingReader(r, [][]byte{[]byte(secret)}, [][]byte{[]byte("PH")}, func(int) { n++ }))
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Repeat("a", 100) + "PH" + "b" + "PH" + strings.Repeat("c", 7) + "sk-REAL-01"
		if string(out) != want || n != 2 {
			t.Fatalf("got %q (%d matches)", out, n)
		}
	}
}

func testGate(t *testing.T, rules []Rule) *Egress {
	r := &Resolver{static: map[string][]netip.Addr{
		"api.example.com":    {netip.MustParseAddr("93.184.216.34")},
		"rebind.example.com": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")},
		"lan.example.com":    {netip.MustParseAddr("10.0.0.5")},
		"meta.example.com":   {netip.MustParseAddr("169.254.169.254")},
	}}
	return NewEgress(EgressConfig{Mode: ModeEnforce, Rules: rules, Resolver: r})
}

func TestDecide(t *testing.T) {
	g := testGate(t, []Rule{
		{Host: "api.example.com", Port: 443},
		{Host: "rebind.example.com", Port: 443},
		{Host: "lan.example.com", Port: 80},
		{Host: "meta.example.com", Port: 80},
		{Host: "*.cdn.example.com", Port: 443},
		{Host: "10.0.0.9", Port: 5432, LAN: true},
	})
	ctx := context.Background()
	allow := []struct {
		h string
		p int
	}{{"api.example.com", 443}, {"API.EXAMPLE.COM.", 443}, {"10.0.0.9", 5432}}
	for _, c := range allow {
		if d := g.decide(ctx, c.h, c.p); !d.ok {
			t.Errorf("%s:%d should be allowed: %s", c.h, c.p, d.reason)
		}
	}
	deny := []struct {
		h string
		p int
	}{
		{"api.example.com", 80},     // undeclared port
		{"evil.example.com", 443},   // undeclared host
		{"rebind.example.com", 443}, // one answer is loopback
		{"lan.example.com", 80},     // private without lan flag
		{"meta.example.com", 80},    // metadata after resolution
		{"localhost", 443},          // loopback name
		{"metadata.google.internal", 80},
		{"x.cdn.example.com", 443}, // unresolvable in this test
		{"cdn.example.com", 443},   // wildcard does not match the apex
		{"10.0.0.9", 5433},
	}
	for _, c := range deny {
		if d := g.decide(ctx, c.h, c.p); d.ok {
			t.Errorf("%s:%d should be denied", c.h, c.p)
		}
	}
}

func TestPeekSNI(t *testing.T) {
	for _, name := range []string{"api.example.com", ""} {
		a, b := net.Pipe()
		go func() {
			c := tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true})
			c.Handshake()
		}()
		br := bufio.NewReader(b)
		sni, isTLS, replay, err := peekSNI(b, br)
		if err != nil || !isTLS || sni != name || len(replay) == 0 || replay[0] != 0x16 {
			t.Fatalf("name %q: sni=%q tls=%v err=%v", name, sni, isTLS, err)
		}
		a.Close()
		b.Close()
	}
	a, b := net.Pipe()
	go a.Write([]byte("SSH-2.0-OpenSSH\r\n"))
	_, isTLS, _, err := peekSNI(b, bufio.NewReader(b))
	if err != nil || isTLS {
		t.Fatalf("non-TLS stream: tls=%v err=%v", isTLS, err)
	}
	a.Close()
	b.Close()
}

func TestCAIsNameConstrained(t *testing.T) {
	ca, err := NewCA("t", []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(ca.CertPEM(), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("pem")
	}
	if _, err := ca.Leaf("api.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(ca.cert.PermittedDNSDomains) != 1 || !ca.cert.PermittedDNSDomainsCritical {
		t.Fatal("name constraints missing")
	}
}

// An endless request head must be cut off instead of buffered by the core.
func TestRequestHeadIsBounded(t *testing.T) {
	g := testGate(t, nil)
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { g.handle(b); close(done) }()
	go io.Copy(io.Discard, a)
	a.SetWriteDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(a, "GET http://api.example.com/ HTTP/1.1\r\nX-Fill: "); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("a"), 64<<10)
	sent := 0
	for sent < 4*maxRequestHead {
		n, err := a.Write(chunk)
		sent += n
		if err != nil {
			break
		}
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the gate kept reading an oversized request head")
	}
	if sent > maxRequestHead+2*len(chunk) {
		t.Fatalf("the gate read %d bytes of request head (limit %d)", sent, maxRequestHead)
	}
	a.Close()
}

func TestHeadLimiterOnlyLimitsWhileArmed(t *testing.T) {
	h := &headLimiter{r: strings.NewReader(strings.Repeat("x", 3*maxRequestHead))}
	h.arm()
	n, err := io.Copy(io.Discard, h)
	if n != maxRequestHead || !errors.Is(err, errHeadTooLarge) {
		t.Fatalf("armed: read %d, err %v", n, err)
	}
	h.disarm()
	if n, err := io.Copy(io.Discard, h); n != 2*maxRequestHead || err != nil {
		t.Fatalf("disarmed: read %d, err %v", n, err)
	}
}

// Data carried in the URL and headers counts against the upload limit.
func TestUploadLimitCountsRequestHead(t *testing.T) {
	g := testGate(t, nil)
	g.cfg.Usage = &Usage{bytes: map[string]int64{}}
	rule := &Rule{Host: "api.example.com", Port: 80, UploadLimit: 1000}
	req, _ := http.NewRequest("GET", "http://api.example.com/?d="+strings.Repeat("x", 2000), nil)
	var out bytes.Buffer
	if g.forward(&out, req, "http", "api.example.com", 80, rule) {
		t.Fatal("request over the upload limit was forwarded")
	}
	if !strings.Contains(out.String(), " 403 ") {
		t.Fatalf("expected a 403, got %q", out.String())
	}
}

// A real secret is never sent in clear text to a TLS port.
func TestNoPlaintextSecretToTLSPort(t *testing.T) {
	g := testGate(t, []Rule{{Host: "api.example.com", Port: 443}})
	g.cfg.Secrets = []SecretBinding{{Name: "K", Host: "api.example.com", Header: "X-Api-Key", Placeholder: "PH", Real: "REAL"}}
	req, _ := http.NewRequest("GET", "http://api.example.com:443/", nil)
	req.Header.Set("X-Api-Key", "PH")
	var out bytes.Buffer
	if g.forward(&out, req, "http", "api.example.com", 443, &g.cfg.Rules[0]) || !strings.Contains(out.String(), " 403 ") {
		t.Fatalf("plaintext request carrying a secret to :443 was not refused: %q", out.String())
	}
}

func TestIngressRejectsOtherOriginsAndStripsForeignTokens(t *testing.T) {
	var seen http.Header
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	defer app.Close()
	dial := func(int) (net.Conn, error) { return net.Dial("tcp", app.Listener.Addr().String()) }
	in, err := StartIngress(8000, 0, "tok", dial, nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", in.HostPort)
	do := func(origin string) int {
		req, _ := http.NewRequest("POST", base+"/act", nil)
		req.Header.Set(TokenHeader, "tok")
		req.Header.Set("Cookie", "warp_token_9999=other-shell-token; session=keep")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("http://127.0.0.1:9999"); c != http.StatusForbidden {
		t.Errorf("request from another local origin: status %d, want 403", c)
	}
	if c := do("https://evil.example"); c != http.StatusForbidden {
		t.Errorf("cross-site request: status %d, want 403", c)
	}
	seen = nil
	if c := do(base); c != http.StatusOK {
		t.Errorf("same-origin request: status %d, want 200", c)
	}
	if c := do(""); c != http.StatusOK {
		t.Errorf("request without Origin: status %d, want 200", c)
	}
	if got := seen.Get("Cookie"); got != "session=keep" {
		t.Errorf("cookies forwarded to the app: %q, want only the app's own", got)
	}
}

// TLS to a named host without a server name cannot be tied to that host.
func TestTunnelWithoutSNIIsRefused(t *testing.T) {
	g := testGate(t, []Rule{{Host: "api.example.com", Port: 443}})
	notes := make(chan string, 4)
	g.cfg.Notify = func(s string) { notes <- s }
	a, b := net.Pipe()
	go g.handle(b)
	defer a.Close()
	io.WriteString(a, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
	br := bufio.NewReader(a)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	go tls.Client(&bufConn{a, br}, &tls.Config{InsecureSkipVerify: true}).Handshake() // no ServerName: no SNI
	select {
	case n := <-notes:
		if !strings.Contains(n, "沒有伺服器名稱") {
			t.Fatalf("unexpected block reason: %s", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a TLS hello without SNI was not refused")
	}
}

// tunnelGate serves the gate on a local listener; every decided dial goes to
// the given upstream instead of the resolved (public, test-only) address.
func tunnelGate(t *testing.T, mode string, upstream string) (proxy string, rec *evidence.Recorder) {
	t.Helper()
	r := &Resolver{static: map[string][]netip.Addr{"docs.example.org": {netip.MustParseAddr("93.184.216.34")}}}
	ca, err := NewCA("t", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec = evidence.NewRecorder()
	g := NewEgress(EgressConfig{Mode: mode, Rules: []Rule{{Host: "docs.example.org", Port: 80}}, Resolver: r, CA: ca, Recorder: rec})
	g.testDial = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr != "93.184.216.34:80" {
			t.Errorf("dial to unexpected address %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go g.Serve(ln)
	return ln.Addr().String(), rec
}

// TestPlainHTTPInsideConnect: a CONNECT tunnel carrying plain HTTP (what
// Node's fetch does for http:// URLs) must work when the gate inspects the
// tunnel (record mode always does), and the Host header must still match.
func TestPlainHTTPInsideConnect(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s %s", r.Host, r.URL.Path)
	}))
	defer up.Close()
	for _, mode := range []string{ModeRecord, ModeEnforce} {
		proxy, rec := tunnelGate(t, mode, up.Listener.Addr().String())
		c, err := net.Dial("tcp", proxy)
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		fmt.Fprint(c, "CONNECT docs.example.org:80 HTTP/1.1\r\nHost: docs.example.org:80\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: CONNECT: %v %v", mode, resp, err)
		}
		for i := 0; i < 2; i++ { // keep-alive inside the tunnel
			fmt.Fprint(c, "GET /page HTTP/1.1\r\nHost: docs.example.org\r\n\r\n")
			resp, err = http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("%s: request %d: %v", mode, i, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || string(b) != "hello docs.example.org /page" {
				t.Fatalf("%s: request %d: HTTP %d %q", mode, i, resp.StatusCode, b)
			}
		}
		c.Close()
		if mode == ModeRecord {
			// When the tunnel is inspected, a Host header naming another
			// host is refused. (An uninspected enforce-mode tunnel is a
			// byte pipe to the already decided address.)
			c, _ := net.Dial("tcp", proxy)
			br := bufio.NewReader(c)
			fmt.Fprint(c, "CONNECT docs.example.org:80 HTTP/1.1\r\nHost: docs.example.org:80\r\n\r\nGET / HTTP/1.1\r\nHost: evil.example\r\n\r\n")
			http.ReadResponse(br, nil)
			resp, err = http.ReadResponse(br, nil)
			c.Close()
			if err != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Warp-Blocked") == "" {
				t.Fatalf("%s: mismatched Host must be blocked: %v %v", mode, resp, err)
			}
			found := false
			for _, e := range rec.Events() {
				if e.Channel == evidence.ChanEgress && e.Host == "docs.example.org" && e.Port == 80 && e.Decision == "allowed" {
					found = true
				}
			}
			if !found {
				t.Fatalf("record mode did not record the tunnel as allowed: %+v", rec.Events())
			}
		}
	}
}

// TestConnectToLoopbackStillDenied: the gate itself refuses tunnels and
// requests aimed at loopback, whatever the shell's NO_PROXY says.
func TestConnectToLoopbackStillDenied(t *testing.T) {
	for _, mode := range []string{ModeRecord, ModeEnforce} {
		proxy, _ := tunnelGate(t, mode, "127.0.0.1:1")
		for _, req := range []string{
			"CONNECT 127.0.0.1:8123 HTTP/1.1\r\nHost: 127.0.0.1:8123\r\n\r\n",
			"CONNECT localhost:8123 HTTP/1.1\r\nHost: localhost:8123\r\n\r\n",
			"CONNECT [::1]:8123 HTTP/1.1\r\nHost: [::1]:8123\r\n\r\n",
			"GET http://127.0.0.1:8123/ HTTP/1.1\r\nHost: 127.0.0.1:8123\r\n\r\n",
			"GET http://localhost:8123/ HTTP/1.1\r\nHost: localhost:8123\r\n\r\n",
		} {
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprint(c, req)
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			c.Close()
			if err != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Warp-Blocked") == "" {
				t.Fatalf("%s: %q must be blocked: %v %v", mode, strings.SplitN(req, "\r\n", 2)[0], resp, err)
			}
		}
	}
}

// TestTunnelHTTPHeadIsBounded: plain HTTP inside an inspected tunnel is
// subject to the same request-head bound as every other request.
func TestTunnelHTTPHeadIsBounded(t *testing.T) {
	proxy, _ := tunnelGate(t, ModeRecord, "127.0.0.1:1")
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	fmt.Fprint(c, "CONNECT docs.example.org:80 HTTP/1.1\r\nHost: docs.example.org:80\r\n\r\n")
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	go func() {
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: docs.example.org\r\nX-Big: ")
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for i := 0; i < 40; i++ { // 2.5 MiB > maxRequestHead
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}()
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("an oversized head inside the tunnel must be refused: %v %v", resp, err)
	}
}
