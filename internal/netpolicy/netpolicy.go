// Package netpolicy classifies destination addresses and host names. The
// egress gate applies these checks to every resolved IP right before it
// dials that exact IP, which defeats DNS rebinding.
package netpolicy

import (
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// Class is an address category.
type Class string

const (
	Public      Class = "public"
	Loopback    Class = "loopback"
	Private     Class = "private"     // RFC1918, ULA, CGNAT, documentation & benchmark ranges
	LinkLocal   Class = "link-local"  // includes cloud metadata 169.254.169.254
	Metadata    Class = "metadata"    // well-known cloud metadata addresses
	Unspecified Class = "unspecified" // 0.0.0.0/8, ::
	Multicast   Class = "multicast"
	Reserved    Class = "reserved" // broadcast, 240/4, translation prefixes, ...
	HostLocal   Class = "host-local"
)

// Describe returns a human readable (zh-TW) description.
func (c Class) Describe() string {
	switch c {
	case Loopback:
		return "主機本機迴路位址"
	case Private:
		return "區域網路／私有位址"
	case LinkLocal:
		return "連結本地位址"
	case Metadata:
		return "雲端中繼資料位址"
	case Unspecified:
		return "未指定位址"
	case Multicast:
		return "群播位址"
	case Reserved:
		return "保留位址"
	case HostLocal:
		return "本機網路介面位址"
	}
	return "公開位址"
}

var metadataAddrs = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true,
	netip.MustParseAddr("169.254.170.2"):   true, // ECS task metadata
	netip.MustParseAddr("100.100.100.200"): true, // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"):   true, // AWS IPv6 IMDS
	netip.MustParseAddr("168.63.129.16"):   true, // Azure WireServer (a public-range address only reachable from the VM)
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	unspecified = mustPrefixes("0.0.0.0/8", "::/128")
	private     = mustPrefixes(
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"100.64.0.0/10",                                     // CGNAT
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", // documentation (used as LANs in practice)
		"198.18.0.0/15", // benchmarking
		"fc00::/7",      // ULA
		"2001:db8::/32", // documentation
	)
	reserved = mustPrefixes(
		"192.0.0.0/24",   // IETF protocol assignments
		"240.0.0.0/4",    // reserved + broadcast
		"64:ff9b::/96",   // NAT64 (embeds IPv4)
		"64:ff9b:1::/48", // local-use NAT64
		"2002::/16",      // 6to4 (embeds IPv4)
		"2001::/32",      // Teredo (embeds IPv4)
		"100::/64",       // discard
		"fec0::/10",      // deprecated site-local
		"::/96",          // IPv4-compatible (deprecated)
	)
)

// Classify returns the category of ip, ignoring host-local interfaces.
func Classify(ip netip.Addr) Class {
	ip = ip.Unmap().WithZone("")
	if metadataAddrs[ip] {
		return Metadata
	}
	switch {
	case !ip.IsValid():
		return Reserved
	case ip.IsLoopback():
		return Loopback
	case ip.IsUnspecified():
		return Unspecified
	case ip.IsLinkLocalUnicast():
		return LinkLocal
	case ip.IsMulticast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return Multicast
	}
	for _, p := range unspecified {
		if p.Contains(ip) {
			return Unspecified
		}
	}
	for _, p := range reserved {
		if p.Contains(ip) {
			return Reserved
		}
	}
	for _, p := range private {
		if p.Contains(ip) {
			return Private
		}
	}
	return Public
}

// HostAddrs returns the addresses configured on this host's interfaces.
func HostAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if na, ok := netip.AddrFromSlice(ip); ok {
			out[na.Unmap().WithZone("")] = true
		}
	}
	return out
}

// Check decides whether a resolved IP may be dialled. allowLAN permits the
// Private class only (never loopback, link-local, metadata or host-local).
func Check(ip netip.Addr, allowLAN bool, hostAddrs map[netip.Addr]bool) (Class, bool) {
	ip = ip.Unmap().WithZone("")
	c := Classify(ip)
	if hostAddrs[ip] && (c == Public || c == Private) {
		return HostLocal, false
	}
	switch c {
	case Public:
		return c, true
	case Private:
		return c, allowLAN
	}
	return c, false
}

var metadataNames = map[string]bool{
	"metadata.google.internal":     true,
	"metadata.goog":                true,
	"metadata":                     true,
	"instance-data":                true,
	"instance-data.ec2.internal":   true,
	"metadata.azure.com":           true,
	"metadata.platformequinix.com": true,
}

// IsMetadataName reports well-known metadata host names.
func IsMetadataName(host string) bool {
	return metadataNames[NormalizeHost(host)]
}

// IsLoopbackName reports names that always mean the local machine.
func IsLoopbackName(host string) bool {
	h := NormalizeHost(host)
	return h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		h == "localhost.localdomain" || h == "ip6-localhost" || h == "ip6-loopback"
}

// NormalizeHost lower-cases and strips a trailing dot and IPv6 brackets.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether h is a lower-case, fully qualified DNS name
// with at least two labels (single-label names resolve via local search
// domains and are therefore rejected).
func ValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || h != strings.ToLower(h) {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	// The last label must not be all digits (avoids ambiguous numeric hosts).
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// ParseIPLiteral parses an IP literal (without brackets) strictly.
func ParseIPLiteral(h string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(NormalizeHost(h))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}
