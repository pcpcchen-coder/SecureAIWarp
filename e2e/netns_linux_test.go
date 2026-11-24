//go:build linux

package e2e

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This file builds a small, isolated test network: an upstream server runs
// in its own network namespace and is reachable from the host only through
// a veth pair. It gives the egress gate a "public" destination to talk to
// without touching the real Internet and without weakening any gate check.

func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func ifinfomsg() []byte { return make([]byte, unix.SizeofIfInfomsg) }

// createVeth creates host-side `host` and moves its peer `peer` into the
// network namespace of process pid.
func createVeth(host, peer string, pid int) error {
	pidb := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidb, uint32(pid))
	peerInfo := append(ifinfomsg(), nlAttr(unix.IFLA_IFNAME, cstr(peer))...)
	peerInfo = append(peerInfo, nlAttr(unix.IFLA_NET_NS_PID, pidb)...)
	infoData := nlAttr(1 /* VETH_INFO_PEER */, peerInfo)
	linkInfo := append(nlAttr(unix.IFLA_INFO_KIND, cstr("veth")), nlAttr(unix.IFLA_INFO_DATA, infoData)...)
	payload := append(ifinfomsg(), nlAttr(unix.IFLA_IFNAME, cstr(host))...)
	payload = append(payload, nlAttr(unix.IFLA_LINKINFO, linkInfo)...)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(payload))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.LittleEndian.PutUint16(msg[4:6], unix.RTM_NEWLINK)
	binary.LittleEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	msg = append(msg, payload...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.NLMSG_HDRLEN+4 {
		return fmt.Errorf("short netlink reply")
	}
	if binary.LittleEndian.Uint16(buf[4:6]) == unix.NLMSG_ERROR {
		if code := int32(binary.LittleEndian.Uint32(buf[16:20])); code != 0 {
			return fmt.Errorf("RTM_NEWLINK: %v", syscall.Errno(-code))
		}
	}
	return nil
}

// configureIface assigns an IPv4 address/24 and brings the interface up.
func configureIface(name string, ip net.IP) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if ip != nil {
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			return err
		}
		if err := ifr.SetInet4Addr(ip.To4()); err != nil {
			return err
		}
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifr); err != nil {
			return fmt.Errorf("SIOCSIFADDR %s: %w", name, err)
		}
		mask, _ := unix.NewIfreq(name)
		mask.SetInet4Addr(net.IPv4(255, 255, 255, 0).To4())
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, mask); err != nil {
			return fmt.Errorf("SIOCSIFNETMASK %s: %w", name, err)
		}
	}
	ifr, _ := unix.NewIfreq(name)
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func waitIface(name string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("interface %s did not appear", name)
}
