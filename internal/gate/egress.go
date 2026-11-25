package gate

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/ledger"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/netpolicy"
)

// Modes.
const (
	ModeRecord  = "record"
	ModeEnforce = "enforce"
)

// Rule is one allowed destination (from network.egress).
type Rule struct {
	Host        string
	Port        int
	LAN         bool
	UploadLimit int64 // bytes per day, 0 = unlimited
	Grant       string
}

// SecretBinding maps a placeholder to the real value for one host+header.
type SecretBinding struct {
	Name        string
	Host        string
	Header      string
	Placeholder string
	Real        string
}

// Decoy is a fake secret value used in record mode.
type Decoy struct {
	Name  string
	Value string
}

// EgressConfig configures the egress gate.
type EgressConfig struct {
	Mode  string
	Rules []Rule // enforce: the only allowed destinations
	// RecordOnly, in record mode, restricts connections to these
	// destinations (evidence replay only re-checks declared behaviour and
	// must not open the network to whatever the replayed command wants).
	RecordOnly []Rule
	Secrets    []SecretBinding // enforce: gate-only secrets to inject
	Redact     []string        // real values that must never flow back into the shell
	Decoys     []Decoy         // record: decoy values to look for
	CA         *CA             // required if any connection must be inspected
	Resolver   *Resolver
	Ledger     *ledger.Ledger
	Recorder   *evidence.Recorder
	Usage      *Usage
	Notify     func(string) // human-readable block notices
	// DialTimeout for upstream connections.
	DialTimeout time.Duration
}

// Egress is the egress gate.
type Egress struct {
	cfg       EgressConfig
	transport *http.Transport
	hostMu    sync.Mutex
	hostAddrs map[netip.Addr]bool
	hostAt    time.Time
	wg        sync.WaitGroup
}

// NewEgress builds the gate.
func NewEgress(cfg EgressConfig) *Egress {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Notify == nil {
		cfg.Notify = func(string) {}
	}
	g := &Egress{cfg: cfg}
	g.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dialForTransport,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{}, // HTTP/1.1 only
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
	}
	return g
}

// Serve accepts proxy connections until the listener is closed.
func (g *Egress) Serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.handle(c)
		}()
	}
}

// Close releases idle upstream connections.
func (g *Egress) Close() { g.transport.CloseIdleConnections() }

type decision struct {
	ok     bool
	reason string
	rule   *Rule
	ips    []netip.Addr
}

func (g *Egress) hostAddresses() map[netip.Addr]bool {
	g.hostMu.Lock()
	defer g.hostMu.Unlock()
	if g.hostAddrs == nil || time.Since(g.hostAt) > 5*time.Second {
		g.hostAddrs = netpolicy.HostAddrs()
		g.hostAt = time.Now()
	}
	return g.hostAddrs
}

func hostEqual(pattern, host string) bool {
	if a, err := netip.ParseAddr(pattern); err == nil {
		b, err := netip.ParseAddr(host)
		return err == nil && a.Unmap() == b.Unmap()
	}
	return evidence.HostMatches(pattern, host)
}

// decide applies every egress check except the dial itself.
func (g *Egress) decide(ctx context.Context, host string, port int) decision {
	host = netpolicy.NormalizeHost(host)
	if port < 1 || port > 65535 {
		return decision{reason: "無效的連接埠"}
	}
	if netpolicy.IsMetadataName(host) {
		return decision{reason: "雲端中繼資料位址"}
	}
	if netpolicy.IsLoopbackName(host) {
		return decision{reason: "主機本機"}
	}
	var ips []netip.Addr
	if ip, ok := netpolicy.ParseIPLiteral(host); ok {
		ips = []netip.Addr{ip}
	} else if !netpolicy.ValidHostname(host) {
		return decision{reason: "無效的主機名稱"}
	}
	var rule *Rule
	rules, restricted := g.cfg.Rules, g.cfg.Mode == ModeEnforce
	if g.cfg.Mode == ModeRecord && g.cfg.RecordOnly != nil {
		rules, restricted = g.cfg.RecordOnly, true
	}
	if restricted {
		for i := range rules {
			r := &rules[i]
			if r.Port == port && hostEqual(r.Host, host) {
				rule = r
				break
			}
		}
		if rule == nil {
			return decision{reason: "未宣告的連線目的地"}
		}
	}
	if ips == nil {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var err error
		ips, err = g.cfg.Resolver.Lookup(lctx, host)
		if err != nil {
			return decision{rule: rule, reason: "無法解析主機名稱"}
		}
	}
	allowLAN := rule != nil && rule.LAN
	ha := g.hostAddresses()
	for _, ip := range ips {
		if class, ok := netpolicy.Check(ip, allowLAN, ha); !ok {
			return decision{rule: rule, reason: fmt.Sprintf("解析結果 %s 屬於%s", ip, class.Describe())}
		}
	}
	return decision{ok: true, rule: rule, ips: ips}
}

func (g *Egress) dialIPs(ctx context.Context, ips []netip.Addr, port int) (net.Conn, error) {
	var lastErr error
	d := net.Dialer{Timeout: g.cfg.DialTimeout}
	for _, ip := range ips {
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("沒有可連線的位址")
	}
	return nil, lastErr
}

// dialForTransport re-applies the full decision for every upstream dial
// made by the HTTP transport (inspected and plain-HTTP requests).
func (g *Egress) dialForTransport(ctx context.Context, network, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(ps)
	d := g.decide(ctx, host, port)
	if !d.ok {
		return nil, fmt.Errorf("blocked: %s", d.reason)
	}
	return g.dialIPs(ctx, d.ips, port)
}

func (g *Egress) logDecision(action, target string, d decision, extra string) {
	dec := "allow"
	detail := extra
	if !d.ok {
		dec = "deny"
		detail = strings.TrimSpace(d.reason + " " + extra)
		g.cfg.Notify(fmt.Sprintf("已阻擋對外連線 %s（%s）", target, d.reason))
	}
	g.cfg.Ledger.Log("egress", action, dec, target, detail)
}

func (g *Egress) record(host string, port int, op string, d decision) {
	if g.cfg.Recorder == nil {
		return
	}
	dec := "allowed"
	if !d.ok {
		dec = "blocked"
	}
	g.cfg.Recorder.Add(evidence.Event{Channel: evidence.ChanEgress, Host: netpolicy.NormalizeHost(host), Port: port, Op: op, Decision: dec, Reason: d.reason})
}

func writeBlocked(w io.Writer, status int, reason string) {
	body := "SecureAIWarp: 已阻擋（" + reason + "）\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nX-Warp-Blocked: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), url.QueryEscape(reason), len(body), body)
}

// maxRequestHead bounds the request line plus headers of one proxied
// request. http.ReadRequest itself has no limit, and the gate's memory is
// outside the shell's memory limit: without a bound the app could make the
// core buffer an endless header line and exhaust the host's memory.
const maxRequestHead = 1 << 20

var errHeadTooLarge = errors.New("request head too large")

// headLimiter fails reads once more than the armed budget has been consumed
// while a request head is being parsed; bodies are read with it disarmed.
type headLimiter struct {
	r     io.Reader
	left  int64
	armed bool
}

func (h *headLimiter) arm()    { h.left, h.armed = maxRequestHead, true }
func (h *headLimiter) disarm() { h.armed = false }

func (h *headLimiter) Read(p []byte) (int, error) {
	if !h.armed {
		return h.r.Read(p)
	}
	if h.left <= 0 {
		return 0, errHeadTooLarge
	}
	if int64(len(p)) > h.left {
		p = p[:h.left]
	}
	n, err := h.r.Read(p)
	h.left -= int64(n)
	return n, err
}

func (g *Egress) handle(c net.Conn) {
	defer c.Close()
	lim := &headLimiter{r: c}
	br := bufio.NewReader(lim)
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		lim.arm()
		req, err := http.ReadRequest(br)
		lim.disarm()
		if err != nil {
			if errors.Is(err, errHeadTooLarge) {
				g.cfg.Ledger.Log("egress", "request", "deny", "", "請求標頭超過大小上限")
				writeBlocked(c, http.StatusRequestHeaderFieldsTooLarge, "請求標頭過大")
			}
			return
		}
		c.SetReadDeadline(time.Time{})
		if req.Method == http.MethodConnect {
			g.handleConnect(c, br, req)
			return
		}
		if !g.handlePlain(c, req) {
			return
		}
	}
}

func splitTarget(hostport string, defPort int) (string, int, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		if defPort == 0 {
			return "", 0, err
		}
		host, ps = hostport, strconv.Itoa(defPort)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return "", 0, err
	}
	return netpolicy.NormalizeHost(host), port, nil
}

func (g *Egress) needsInspection(host string) bool {
	if g.cfg.Mode == ModeRecord {
		return true
	}
	for _, s := range g.cfg.Secrets {
		if hostEqual(s.Host, host) {
			return true
		}
	}
	return false
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (g *Egress) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := splitTarget(req.Host, 0)
	target := req.Host
	if err != nil {
		writeBlocked(c, http.StatusBadRequest, "無效的 CONNECT 目的地")
		return
	}
	target = fmt.Sprintf("%s:%d", host, port)
	d := g.decide(context.Background(), host, port)
	g.record(host, port, "connect", d)
	if !d.ok {
		g.logDecision("connect", target, d, "")
		writeBlocked(c, http.StatusForbidden, d.reason)
		return
	}
	inspect := g.needsInspection(host)
	if inspect && g.cfg.CA == nil {
		d.ok, d.reason = false, "需要檢視內容但沒有本機憑證"
		g.logDecision("connect", target, d, "")
		writeBlocked(c, http.StatusBadGateway, d.reason)
		return
	}
	if !inspect {
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Without terminating TLS we still check that the TLS server name
		// matches the approved host (prevents domain fronting via SNI).
		sni, isTLS, replay, err := peekSNI(c, br)
		if err != nil {
			d.ok, d.reason = false, "無法檢查 TLS 伺服器名稱"
			g.logDecision("connect", target, d, err.Error())
			return
		}
		if isTLS && sni != "" && netpolicy.NormalizeHost(sni) != host {
			d.ok, d.reason = false, "TLS 伺服器名稱 "+sni+" 與核准的主機不符"
			g.logDecision("connect", target, d, "")
			return
		}
		// A TLS client that names a host always sends that name. A hello
		// without one, to a named host, lets a shared front end pick its
		// default site while the real destination hides in the encrypted
		// Host header: the same fronting the check above exists to stop.
		if _, isIP := netpolicy.ParseIPLiteral(host); isTLS && sni == "" && !isIP {
			d.ok, d.reason = false, "TLS 交握沒有伺服器名稱，無法確認目的地是核准的主機"
			g.logDecision("connect", target, d, "")
			return
		}
		up, err := g.dialIPs(context.Background(), d.ips, port)
		if err != nil {
			g.cfg.Ledger.Log("egress", "connect", "allow", target, "上游連線失敗："+err.Error())
			return
		}
		g.logDecision("connect", target, d, "tunnel sni="+sni)
		defer up.Close()
		if len(replay) > 0 {
			if _, err := up.Write(replay); err != nil {
				return
			}
		}
		g.pipe(&bufConn{c, br}, up, d.rule, target)
		return
	}
	g.logDecision("connect", target, d, "inspect")
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	leaf, err := g.cfg.CA.Leaf(host)
	if err != nil {
		return
	}
	tc := tls.Server(&bufConn{c, br}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName != "" && netpolicy.NormalizeHost(h.ServerName) != host {
				return nil, fmt.Errorf("SNI %q 與 CONNECT 目的地不符", h.ServerName)
			}
			return leaf, nil
		},
	})
	tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.Handshake(); err != nil {
		g.cfg.Ledger.Log("egress", "tls", "deny", target, "TLS 交握失敗（應用可能不信任殼的本機憑證或做了憑證綁定）："+err.Error())
		return
	}
	tc.SetDeadline(time.Time{})
	tlim := &headLimiter{r: tc}
	tbr := bufio.NewReader(tlim)
	for {
		tc.SetReadDeadline(time.Now().Add(5 * time.Minute))
		tlim.arm()
		r, err := http.ReadRequest(tbr)
		tlim.disarm()
		if err != nil {
			if errors.Is(err, errHeadTooLarge) {
				g.cfg.Ledger.Log("egress", "request", "deny", target, "請求標頭超過大小上限")
				writeBlocked(tc, http.StatusRequestHeaderFieldsTooLarge, "請求標頭過大")
			}
			return
		}
		tc.SetReadDeadline(time.Time{})
		if !g.forward(tc, r, "https", host, port, d.rule) {
			return
		}
	}
}

func (g *Egress) handlePlain(c net.Conn, req *http.Request) bool {
	if req.URL == nil || !req.URL.IsAbs() || req.URL.Scheme != "http" {
		writeBlocked(c, http.StatusBadRequest, "只接受 http:// 絕對網址或 CONNECT")
		return false
	}
	host, port, err := splitTarget(req.URL.Host, 80)
	if err != nil {
		writeBlocked(c, http.StatusBadRequest, "無效的目的地")
		return false
	}
	target := fmt.Sprintf("%s:%d", host, port)
	d := g.decide(context.Background(), host, port)
	g.record(host, port, "http", d)
	g.logDecision("http", target, d, req.Method+" "+req.URL.Path)
	if !d.ok {
		writeBlocked(c, http.StatusForbidden, d.reason)
		return false
	}
	return g.forward(c, req, "http", host, port, d.rule)
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, k := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// forward relays one HTTP request (already inside the decided connection)
// and its response. It returns whether the client connection may be reused.
func (g *Egress) forward(w io.Writer, req *http.Request, scheme, host string, port int, rule *Rule) bool {
	target := fmt.Sprintf("%s:%d", host, port)
	if req.Host != "" {
		hh, hp, err := splitTarget(req.Host, map[string]int{"http": 80, "https": 443}[scheme])
		if err != nil || hh != host || (hp != port && strings.Contains(req.Host, ":")) {
			d := decision{reason: "Host 標頭與連線目的地不符"}
			g.logDecision("request", target, d, req.Host)
			writeBlocked(w, http.StatusForbidden, d.reason)
			return false
		}
	}
	out := &http.Request{
		Method:        req.Method,
		URL:           &url.URL{Scheme: scheme, Host: target, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery},
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        req.Header.Clone(),
		Host:          host,
		ContentLength: req.ContentLength,
	}
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		out.Host = target
	}
	stripHop(out.Header)
	out.Header.Del("Accept-Encoding") // the transport negotiates gzip and decodes it for redaction
	if req.Body != nil && req.ContentLength != 0 {
		out.Body = req.Body
	}
	if out.ContentLength < 0 && len(req.TransferEncoding) > 0 {
		out.TransferEncoding = []string{"chunked"}
	}

	// Record mode: look for decoy secrets.
	if g.cfg.Mode == ModeRecord && len(g.cfg.Decoys) > 0 {
		g.scanDecoys(out, host)
	}
	// The upload limit covers everything the app can put data in, not only
	// the body: otherwise it is bypassed by exfiltrating through the URL and
	// headers of body-less requests.
	if rule != nil && rule.UploadLimit > 0 && g.cfg.Usage != nil {
		if err := g.cfg.Usage.Add(target, requestHeadSize(req), rule.UploadLimit); err != nil {
			g.cfg.Notify(fmt.Sprintf("已阻擋對 %s 的上傳（超過每日上傳上限）", target))
			g.cfg.Ledger.Log("egress", "upload", "deny", target, "超過每日上傳上限")
			writeBlocked(w, http.StatusForbidden, "超過每日上傳上限")
			return false
		}
	}
	// Enforce mode: inject real values for bound secrets.
	injected := []string{}
	for _, s := range g.cfg.Secrets {
		if !hostEqual(s.Host, host) {
			continue
		}
		vals := out.Header.Values(s.Header)
		if len(vals) == 0 {
			continue
		}
		// Never put a real secret on the wire in clear text towards a TLS
		// port: the app picks the scheme, and plain http:// to :443 would
		// hand the key to anyone on the network path.
		if scheme == "http" && port == 443 {
			carries := false
			for _, v := range vals {
				carries = carries || strings.Contains(v, s.Placeholder)
			}
			if carries {
				d := decision{reason: "拒絕以明文 HTTP 把機密 " + s.Name + " 送往 TLS 連接埠"}
				g.logDecision("request", target, d, "")
				writeBlocked(w, http.StatusForbidden, d.reason)
				return false
			}
		}
		var nv []string
		did := false
		for _, v := range vals {
			if strings.Contains(v, s.Placeholder) {
				v = strings.ReplaceAll(v, s.Placeholder, s.Real)
				did = true
			}
			nv = append(nv, v)
		}
		if did {
			out.Header[http.CanonicalHeaderKey(s.Header)] = nv
			injected = append(injected, s.Name)
		}
	}
	if len(injected) > 0 {
		g.cfg.Ledger.Log("secret", "inject", "allow", target, "注入 "+strings.Join(injected, ",")+" 至標頭")
	}
	if out.Body != nil && rule != nil && rule.UploadLimit > 0 && g.cfg.Usage != nil {
		out.Body = &countingReader{r: out.Body, add: func(n int) error { return g.cfg.Usage.Add(target, int64(n), rule.UploadLimit) }}
	}
	g.cfg.Ledger.Log("egress", "request", "allow", target, req.Method+" "+req.URL.Path)
	resp, err := g.transport.RoundTrip(out)
	if err != nil {
		reason := "上游請求失敗"
		if errors.Is(err, ErrUploadLimit) {
			reason = "超過每日上傳上限"
			g.cfg.Notify(fmt.Sprintf("已阻擋對 %s 的上傳（%s）", target, reason))
			g.cfg.Ledger.Log("egress", "upload", "deny", target, reason)
		}
		writeBlocked(w, http.StatusBadGateway, reason)
		return false
	}
	defer resp.Body.Close()

	// Redact real secret values from the response (headers and body).
	olds, news := g.redactPairs()
	if len(olds) > 0 {
		if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
			g.cfg.Ledger.Log("secret", "redact", "deny", target, "回應使用無法檢視的編碼 "+ce)
			writeBlocked(w, http.StatusBadGateway, "回應使用無法檢視的內容編碼，為避免機密回流而阻擋")
			return false
		}
		for k, vs := range resp.Header {
			for i, v := range vs {
				if nv, ch := replaceAll(v, olds, news); ch {
					vs[i] = nv
					g.cfg.Ledger.Log("secret", "redact", "deny", target, "回應標頭 "+k+" 含有機密真值，已遮蔽")
				}
			}
		}
		resp.Body = io.NopCloser(newReplacingReader(resp.Body, olds, news, func(int) {
			g.cfg.Ledger.Log("secret", "redact", "deny", target, "回應內容含有機密真值，已遮蔽")
		}))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	}
	stripHop(resp.Header)
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	if resp.ContentLength < 0 && req.Method != http.MethodHead && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		resp.TransferEncoding = []string{"chunked"}
	} else {
		resp.TransferEncoding = nil
	}
	resp.Close = req.Close
	resp.Request = req
	if err := resp.Write(w); err != nil {
		return false
	}
	return !req.Close
}

// requestHeadSize approximates the bytes of the request line and headers.
func requestHeadSize(req *http.Request) int64 {
	n := len(req.Method) + len(req.Host) + 16
	if req.URL != nil {
		n += len(req.URL.RequestURI())
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			n += len(k) + len(v) + 4
		}
	}
	return int64(n)
}

// redactPairs maps every real secret value (and every decoy) back to its
// placeholder so that nothing the gate injects can flow back into the shell.
func (g *Egress) redactPairs() (olds, news [][]byte) {
	for _, s := range g.cfg.Secrets {
		olds = append(olds, []byte(s.Real))
		news = append(news, []byte(s.Placeholder))
	}
	for _, r := range g.cfg.Redact {
		dup := false
		for _, o := range olds {
			if string(o) == r {
				dup = true
			}
		}
		if !dup && r != "" {
			olds = append(olds, []byte(r))
			news = append(news, []byte("[warp-redacted]"))
		}
	}
	return
}

func (g *Egress) scanDecoys(out *http.Request, host string) {
	rec := func(name, loc, header string) {
		g.cfg.Recorder.Add(evidence.Event{Channel: evidence.ChanSecret, Name: name, Host: host, Location: loc, Header: strings.ToLower(header)})
		g.cfg.Ledger.Log("secret", "decoy-seen", "info", host, name+" 出現在 "+loc+" "+header)
	}
	for _, d := range g.cfg.Decoys {
		for k, vs := range out.Header {
			for _, v := range vs {
				if strings.Contains(v, d.Value) {
					rec(d.Name, "header", k)
				}
			}
		}
		if strings.Contains(out.URL.RawQuery, d.Value) || strings.Contains(out.URL.Path, d.Value) {
			rec(d.Name, "url", "")
		}
	}
	if out.Body != nil {
		var olds, news [][]byte
		for _, d := range g.cfg.Decoys {
			olds = append(olds, []byte(d.Value))
			news = append(news, []byte(d.Value))
		}
		decoys := g.cfg.Decoys
		out.Body = io.NopCloser(newReplacingReader(out.Body, olds, news, func(i int) { rec(decoys[i].Name, "body", "") }))
	}
}

// pipe copies both directions of a tunnel, counting uploads against the
// rule's daily limit.
func (g *Egress) pipe(client net.Conn, up net.Conn, rule *Rule, target string) {
	done := make(chan struct{}, 2)
	go func() {
		var src io.Reader = client
		if rule != nil && rule.UploadLimit > 0 && g.cfg.Usage != nil {
			src = &countingReader{r: client, add: func(n int) error { return g.cfg.Usage.Add(target, int64(n), rule.UploadLimit) }}
		}
		_, err := io.Copy(up, src)
		if errors.Is(err, ErrUploadLimit) {
			g.cfg.Notify(fmt.Sprintf("已阻擋對 %s 的上傳（超過每日上傳上限）", target))
			g.cfg.Ledger.Log("egress", "upload", "deny", target, "超過每日上傳上限")
			client.Close()
		}
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, up)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

type countingReader struct {
	r   io.Reader
	add func(int) error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if e := c.add(n); e != nil {
			return 0, e
		}
	}
	return n, err
}

func (c *countingReader) Close() error {
	if rc, ok := c.r.(io.Closer); ok {
		return rc.Close()
	}
	return nil
}
