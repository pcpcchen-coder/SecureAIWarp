package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
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
