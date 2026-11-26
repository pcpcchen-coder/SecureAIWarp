package main

// Minimal netlink/ioctl helpers (this machine has no iproute2). Adapted from
// SecureAIWarp/e2e/netns_linux_test.go, but the peer is moved into a
// persistent (bind-mounted) network namespace by file descriptor.

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

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

func createVeth(host, peer string, nsfd int) error {
	fdb := make([]byte, 4)
	binary.LittleEndian.PutUint32(fdb, uint32(nsfd))
	peerInfo := append(ifinfomsg(), nlAttr(unix.IFLA_IFNAME, cstr(peer))...)
	peerInfo = append(peerInfo, nlAttr(unix.IFLA_NET_NS_FD, fdb)...)
	infoData := nlAttr(1 /* VETH_INFO_PEER */, peerInfo)
	linkInfo := append(nlAttr(unix.IFLA_INFO_KIND, cstr("veth")), nlAttr(unix.IFLA_INFO_DATA, infoData)...)
	payload := append(ifinfomsg(), nlAttr(unix.IFLA_IFNAME, cstr(host))...)
	payload = append(payload, nlAttr(unix.IFLA_LINKINFO, linkInfo)...)
	return nlRequest(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, payload)
}

func deleteLink(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil // already gone
	}
	msg := ifinfomsg()
	binary.LittleEndian.PutUint32(msg[4:8], uint32(ifi.Index))
	return nlRequest(unix.RTM_DELLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, msg)
}

func nlRequest(typ uint16, flags uint16, payload []byte) error {
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
	binary.LittleEndian.PutUint16(msg[4:6], typ)
	binary.LittleEndian.PutUint16(msg[6:8], flags)
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
			return fmt.Errorf("netlink: %v", syscall.Errno(-code))
		}
	}
	return nil
}

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
		return fmt.Errorf("SIOCGIFFLAGS %s: %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// cmdVeth: mocknet veth -host mnet0 -peer mnet1 -ns /run/netns/mocknet
func cmdVeth(args []string) error {
	fs := flag.NewFlagSet("veth", flag.ExitOnError)
	host := fs.String("host", "mnet0", "host-side interface")
	peer := fs.String("peer", "mnet1", "namespace-side interface")
	ns := fs.String("ns", "/run/netns/mocknet", "persistent netns file")
	fs.Parse(args)
	if _, err := net.InterfaceByName(*host); err == nil {
		fmt.Printf("veth %s already exists\n", *host)
		return nil
	}
	f, err := os.Open(*ns)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := createVeth(*host, *peer, int(f.Fd())); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}
	fmt.Printf("created veth %s <-> %s (in %s)\n", *host, *peer, *ns)
	return nil
}

// cmdIfup: mocknet ifup -if NAME [-ip A.B.C.D]
func cmdIfup(args []string) error {
	fs := flag.NewFlagSet("ifup", flag.ExitOnError)
	name := fs.String("if", "", "interface")
	ip := fs.String("ip", "", "IPv4 address (/24)")
	fs.Parse(args)
	var p net.IP
	if *ip != "" {
		if p = net.ParseIP(*ip); p == nil {
			return fmt.Errorf("bad ip %q", *ip)
		}
	}
	return configureIface(*name, p)
}

func cmdDellink(args []string) error {
	fs := flag.NewFlagSet("dellink", flag.ExitOnError)
	name := fs.String("if", "", "interface")
	fs.Parse(args)
	return deleteLink(*name)
}
