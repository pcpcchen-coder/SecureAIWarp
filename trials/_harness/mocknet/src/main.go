// Command mocknet is the fake Internet upstream for the SecureAIWarp field
// trial: a host-routed HTTP/HTTPS server that imitates a handful of public
// APIs, plus the tiny network/PKI helpers that up.sh needs.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mocknet serve|pki|veth|ifup|dellink ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "pki":
		err = cmdPKI(os.Args[2:])
	case "veth":
		err = cmdVeth(os.Args[2:])
	case "ifup":
		err = cmdIfup(os.Args[2:])
	case "dellink":
		err = cmdDellink(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mocknet:", err)
		os.Exit(1)
	}
}

// ---- request log ----

type logRec struct {
	Time       string `json:"time"`
	Scheme     string `json:"scheme"`
	Proto      string `json:"proto"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Query      string `json:"query,omitempty"`
	Service    string `json:"service"`
	Key        string `json:"key"`                  // valid | invalid | missing | n/a
	KeyVia     string `json:"key_via,omitempty"`    // x-api-key | authorization-bearer | url-path | ...
	KeyKind    string `json:"key_kind,omitempty"`   // real | warp-placeholder | warp-decoy | other
	KeyPrefix  string `json:"key_prefix,omitempty"` // first characters of what was presented
	Status     int    `json:"status"`
	Bytes      int64  `json:"bytes"`
	DurationMS int64  `json:"duration_ms"`
	Stream     bool   `json:"stream,omitempty"`
	Model      string `json:"model,omitempty"`
	Beta       string `json:"anthropic_beta,omitempty"`
	UA         string `json:"user_agent,omitempty"`
	Remote     string `json:"remote"`
	Note       string `json:"note,omitempty"`
}

type logger struct {
	mu sync.Mutex
	f  *os.File
}

func (l *logger) write(r *logRec) {
	b, _ := json.Marshal(r)
	l.mu.Lock()
	l.f.Write(append(b, '\n'))
	l.mu.Unlock()
}

// recWriter captures status/bytes and supports flushing (SSE).
type recWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *recWriter) WriteHeader(s int) {
	if w.status == 0 {
		w.status = s
	}
	w.ResponseWriter.WriteHeader(s)
}
func (w *recWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}
func (w *recWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// keyInfo classifies a presented credential without storing it whole.
func keyInfo(rec *logRec, via, presented, valid string) bool {
	rec.KeyVia = via
	switch {
	case presented == "":
		rec.Key = "missing"
		return false
	case presented == valid:
		rec.Key, rec.KeyKind = "valid", "real"
	case strings.HasPrefix(presented, "warp-placeholder-"):
		rec.Key, rec.KeyKind = "invalid", "warp-placeholder"
	case strings.HasPrefix(presented, "warp-decoy-"):
		rec.Key, rec.KeyKind = "invalid", "warp-decoy"
	default:
		rec.Key, rec.KeyKind = "invalid", "other"
	}
	p := presented
	if len(p) > 18 {
		p = p[:18] + "…"
	}
	rec.KeyPrefix = p
	return rec.Key == "valid"
}

func randID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hostOnly(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

// ---- server ----

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	ip := fs.String("ip", "192.88.99.10", "address to listen on")
	cert := fs.String("cert", "pki/leaf.pem", "TLS certificate")
	key := fs.String("key", "pki/leaf.key", "TLS key")
	logPath := fs.String("log", "logs/requests.jsonl", "JSONL request log (appended)")
	fs.Parse(args)
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	lg := &logger{f: lf}
	kp, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return err
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &recWriter{ResponseWriter: w}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		rec := &logRec{Time: start.Format(time.RFC3339Nano), Scheme: scheme, Proto: r.Proto, Method: r.Method,
			Host: hostOnly(r.Host), Path: r.URL.Path, Query: r.URL.RawQuery, Key: "n/a", UA: r.UserAgent(), Remote: r.RemoteAddr}
		route(rw, r, rec)
		rec.Status, rec.Bytes, rec.DurationMS = rw.status, rw.n, time.Since(start).Milliseconds()
		lg.write(rec)
	})
	srv443 := &http.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 30 * time.Second}
	srv80 := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
	l443, err := net.Listen("tcp", net.JoinHostPort(*ip, "443"))
	if err != nil {
		return err
	}
	l80, err := net.Listen("tcp", net.JoinHostPort(*ip, "80"))
	if err != nil {
		return err
	}
	fmt.Printf("%s mocknet serving on %s:443 (TLS, h2+http/1.1) and %s:80, log %s\n", time.Now().Format(time.RFC3339), *ip, *ip, *logPath)
	errc := make(chan error, 2)
	go func() { errc <- srv80.Serve(l80) }()
	go func() { errc <- srv443.ServeTLS(l443, "", "") }()
	return <-errc
}

func route(w http.ResponseWriter, r *http.Request, rec *logRec) {
	host := rec.Host
	switch host {
	case "mocknet.health":
		rec.Service = "health"
		fmt.Fprintln(w, "ok")
	case "geocoding-api.open-meteo.com":
		rec.Service = "open-meteo-geocoding"
		geocoding(w, r, rec)
	case "api.open-meteo.com":
		rec.Service = "open-meteo-forecast"
		forecast(w, r, rec)
	case "v6.exchangerate-api.com":
		rec.Service = "exchangerate-api"
		exchange(w, r, rec)
	case "api.anthropic.com":
		rec.Service = "anthropic"
		anthropic(w, r, rec)
	case "example.com", "www.example.com", "docs.example.org":
		rec.Service = "site"
		page(w, r, 200, host)
	case "broken.example.net":
		rec.Service = "site-404"
		page(w, r, 404, host)
	case "slow.example.net":
		rec.Service = "site-slow"
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
			rec.Note = "client gave up during delay"
			return
		}
		page(w, r, 200, host)
	case "redirect.example.net":
		rec.Service = "site-redirect"
		w.Header().Set("Location", "https://example.com/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusFound)
		fmt.Fprint(w, `<html><head><title>302 Found</title></head><body><a href="https://example.com/">Found</a></body></html>`+"\n")
	default:
		rec.Service = "unknown"
		http.Error(w, "mocknet: unknown host "+host, http.StatusMisdirectedRequest)
	}
}

func page(w http.ResponseWriter, r *http.Request, status int, host string) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Cache-Control", "max-age=600")
	w.Header().Set("Last-Modified", "Mon, 13 Jan 2025 20:11:20 GMT")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	title := "Example Domain"
	body := "This domain is for use in documentation examples without needing permission. Avoid use in operations."
	if status == 404 {
		title = "404 Not Found"
		body = "The requested URL " + htmlEscape(r.URL.Path) + " was not found on this server."
	}
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><title>%s</title><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><div><h1>%s</h1><p>%s</p><p><a href="https://iana.org/domains/example">Learn more</a></p><p><small>(mocknet: %s%s)</small></p></div></body></html>`+"\n",
		title, title, body, htmlEscape(host), htmlEscape(r.URL.Path))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
