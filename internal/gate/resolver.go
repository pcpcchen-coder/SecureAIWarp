// Package gate implements the egress gate (HTTP/CONNECT proxy with host
// allow-listing, post-resolution address checks, secret injection and
// response redaction) and the ingress gate (loopback-only reverse proxy
// protected by a one-time token).
package gate

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/netpolicy"
)

// Resolver resolves host names for the gate. The shell itself has no
// resolver at all; only the gate resolves, and every answer is checked by
// netpolicy before the exact checked IP is dialled.
type Resolver struct {
	static map[string][]netip.Addr
}

// NewResolver builds a resolver. If WARP_HOSTS_FILE is set (operator
// configuration of the host running warp, never visible to the app), its
// "IP name..." lines are consulted before DNS. Answers from it are subject
// to exactly the same address checks as DNS answers.
func NewResolver() (*Resolver, error) {
	r := &Resolver{static: map[string][]netip.Addr{}}
	p := os.Getenv("WARP_HOSTS_FILE")
	if p == "" {
		return r, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("無法讀取 WARP_HOSTS_FILE：%w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("WARP_HOSTS_FILE 中的位址無效：%q", fields[0])
		}
		for _, n := range fields[1:] {
			n = netpolicy.NormalizeHost(n)
			r.static[n] = append(r.static[n], ip)
		}
	}
	return r, sc.Err()
}

// Lookup returns every address for host.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = netpolicy.NormalizeHost(host)
	if ips, ok := r.static[host]; ok {
		return ips, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("沒有位址")
	}
	return ips, nil
}
