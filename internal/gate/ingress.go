package gate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/ledger"
)

// TokenParam, TokenHeader and the cookie carry the one-time ingress token.
const (
	TokenParam  = "warp_token"
	TokenHeader = "X-Warp-Token"
)

// cookiePrefix starts the name of every ingress token cookie.
const cookiePrefix = "warp_token_"

// NewToken returns a random 256-bit token.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Ingress exposes one port of the app on the host's 127.0.0.1 only, and
// only to clients presenting the per-run token.
type Ingress struct {
	InnerPort int
	HostPort  int
	Token     string
	srv       *http.Server
	ln        net.Listener
}

// URL returns the first-visit URL including the token.
func (in *Ingress) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?%s=%s", in.HostPort, TokenParam, in.Token)
}

// Close stops the listener.
func (in *Ingress) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in.srv.Shutdown(ctx)
}

// StartIngress listens on 127.0.0.1:preferPort (or a free port) and proxies
// authenticated requests to innerPort inside the shell through dial.
func StartIngress(innerPort, preferPort int, token string, dial func(port int) (net.Conn, error), lg *ledger.Ledger, notify func(string)) (*Ingress, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", preferPort))
	if err != nil {
		ln, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
	}
	hostPort := ln.Addr().(*net.TCPAddr).Port
	in := &Ingress{InnerPort: innerPort, HostPort: hostPort, Token: token, ln: ln}
	cookieName := cookiePrefix + strconv.Itoa(hostPort)
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", innerPort)}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del(TokenHeader)
			pr.Out.Header.Del("X-Forwarded-For")
			q := pr.Out.URL.Query()
			if q.Has(TokenParam) {
				q.Del(TokenParam)
				pr.Out.URL.RawQuery = q.Encode()
			}
			// Remove every ingress token cookie before it reaches the app.
			// Browsers do not separate cookies by port, so the cookie of
			// another shell's gate on 127.0.0.1 arrives here too; passing
			// it on would hand that shell's token to this app.
			var keep []string
			for _, c := range pr.In.Cookies() {
				if !strings.HasPrefix(c.Name, cookiePrefix) {
					keep = append(keep, c.Name+"="+c.Value)
				}
			}
			pr.Out.Header.Del("Cookie")
			if len(keep) > 0 {
				pr.Out.Header.Set("Cookie", strings.Join(keep, "; "))
			}
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// The app may still be starting: retry "connection refused"
				// for a few seconds instead of failing the first request.
				deadline := time.Now().Add(10 * time.Second)
				for {
					c, err := dial(innerPort)
					if err == nil || time.Now().After(deadline) || !strings.Contains(err.Error(), "refused") {
						return c, err
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
				}
			},
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "SecureAIWarp：殼內的應用沒有回應（"+err.Error()+"）", http.StatusBadGateway)
		},
	}
	tokenOK := func(v string) bool {
		return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(token)) == 1
	}
	allowedHosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", hostPort): true,
		fmt.Sprintf("localhost:%d", hostPort): true,
	}
	allowedOrigins := map[string]bool{}
	for h := range allowedHosts {
		allowedOrigins["http://"+h] = true
	}
	tgt := fmt.Sprintf("127.0.0.1:%d->shell:%d", hostPort, innerPort)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHosts[strings.ToLower(r.Host)] {
			lg.Log("ingress", "request", "deny", tgt, "Host 標頭不符："+r.Host)
			http.Error(w, "SecureAIWarp：Host 標頭不符", http.StatusForbidden)
			return
		}
		// A browser request made by a page of another origin carries Origin.
		// Every local port is the same "site", so SameSite does not stop a
		// page served from another port on this machine (another shell's
		// app, say) from sending requests here with the token cookie.
		if o := r.Header.Get("Origin"); o != "" && !allowedOrigins[strings.ToLower(o)] {
			lg.Log("ingress", "request", "deny", tgt, "來自其他來源的請求："+o)
			notify(fmt.Sprintf("已阻擋來自其他網頁來源（%s）的連入請求 %s %s", o, r.Method, r.URL.Path))
			http.Error(w, "SecureAIWarp：不接受其他來源的請求", http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		if tokenOK(q.Get(TokenParam)) {
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				q.Del(TokenParam)
				u := *r.URL
				u.RawQuery = q.Encode()
				lg.Log("ingress", "request", "allow", tgt, "權杖驗證成功（網址參數）")
				http.Redirect(w, r, u.RequestURI(), http.StatusSeeOther)
				return
			}
		} else if !tokenOK(r.Header.Get(TokenHeader)) {
			c, err := r.Cookie(cookieName)
			if err != nil || !tokenOK(c.Value) {
				lg.Log("ingress", "request", "deny", tgt, "缺少或錯誤的權杖："+r.Method+" "+r.URL.Path)
				notify(fmt.Sprintf("已阻擋未帶權杖的連入請求 %s %s", r.Method, r.URL.Path))
				w.Header().Set("WWW-Authenticate", `Bearer realm="SecureAIWarp"`)
				http.Error(w, "SecureAIWarp：需要一次性權杖", http.StatusUnauthorized)
				return
			}
		}
		lg.Log("ingress", "request", "allow", tgt, r.Method+" "+r.URL.Path)
		rp.ServeHTTP(w, r)
	})
	in.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go in.srv.Serve(ln)
	return in, nil
}
