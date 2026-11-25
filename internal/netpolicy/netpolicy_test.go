package netpolicy

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"8.8.8.8":                Public,
		"1.2.3.4":                Public,
		"2606:4700::1111":        Public,
		"127.0.0.1":              Loopback,
		"127.8.9.10":             Loopback,
		"::1":                    Loopback,
		"::ffff:127.0.0.1":       Loopback,
		"10.1.2.3":               Private,
		"172.16.5.4":             Private,
		"192.168.0.1":            Private,
		"100.64.0.1":             Private,
		"192.0.2.10":             Private,
		"fd12::1":                Private,
		"169.254.169.254":        Metadata,
		"fd00:ec2::254":          Metadata,
		"100.100.100.200":        Metadata,
		"169.254.1.1":            LinkLocal,
		"fe80::1":                LinkLocal,
		"0.0.0.0":                Unspecified,
		"0.1.2.3":                Unspecified,
		"::":                     Unspecified,
		"224.0.0.1":              Multicast,
		"ff02::1":                Multicast,
		"255.255.255.255":        Reserved,
		"64:ff9b::7f00:1":        Reserved,
		"2002:7f00:1::":          Reserved,
		"::ffff:169.254.169.254": Metadata,
	}
	for s, want := range cases {
		if got := Classify(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %s want %s", s, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	host := map[netip.Addr]bool{netip.MustParseAddr("203.0.113.7"): true, netip.MustParseAddr("8.8.4.4"): true}
	if _, ok := Check(netip.MustParseAddr("8.8.8.8"), false, host); !ok {
		t.Error("public must pass")
	}
	if c, ok := Check(netip.MustParseAddr("8.8.4.4"), false, host); ok || c != HostLocal {
		t.Error("host-own public address must be blocked")
	}
	if _, ok := Check(netip.MustParseAddr("10.0.0.1"), true, nil); !ok {
		t.Error("lan allowed with flag")
	}
	if _, ok := Check(netip.MustParseAddr("10.0.0.1"), false, nil); ok {
		t.Error("lan blocked without flag")
	}
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "fe80::1", "0.0.0.0"} {
		if _, ok := Check(netip.MustParseAddr(s), true, nil); ok {
			t.Errorf("%s must never pass, even with lan", s)
		}
	}
}

func TestNames(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST.", "a.localhost", "ip6-localhost"} {
		if !IsLoopbackName(h) {
			t.Errorf("%s should be loopback", h)
		}
	}
	if !IsMetadataName("metadata.google.internal.") {
		t.Error("metadata name")
	}
	for h, ok := range map[string]bool{"api.example.com": true, "example": false, "API.example.com": false, "a..b": false, "1.2.3": false, "-a.com": false} {
		if ValidHostname(h) != ok {
			t.Errorf("ValidHostname(%q) != %v", h, ok)
		}
	}
}

func TestAzureWireServerIsMetadata(t *testing.T) {
	ip := netip.MustParseAddr("168.63.129.16")
	if c := Classify(ip); c != Metadata {
		t.Fatalf("168.63.129.16 classified as %s", c)
	}
	if _, ok := Check(ip, true, nil); ok {
		t.Fatal("the Azure WireServer address must never be dialled, even with lan: true")
	}
}
