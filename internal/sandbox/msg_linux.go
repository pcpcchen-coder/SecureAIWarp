//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// msg is one control message between the parent and the shell init.
type msg struct {
	T      string  `json:"t"`
	Config *Config `json:"config,omitempty"`
	ID     int     `json:"id,omitempty"`
	Port   int     `json:"port,omitempty"`
	Code   int     `json:"code,omitempty"`
	Sig    int     `json:"sig,omitempty"`
	Err    string  `json:"err,omitempty"`
}

const maxMsg = 1 << 16

func sendMsg(fd int, m *msg, passFD int) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxMsg {
		return fmt.Errorf("control message too large (%d bytes)", len(b))
	}
	var oob []byte
	if passFD >= 0 {
		oob = unix.UnixRights(passFD)
	}
	return unix.Sendmsg(fd, b, oob, nil, 0)
}

// recvMsg reads one message and at most one passed file descriptor (-1 if none).
func recvMsg(fd int) (*msg, int, error) {
	buf := make([]byte, maxMsg)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		n, oobn, flags, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, -1, err
		}
		if n == 0 && oobn == 0 {
			return nil, -1, errors.New("control channel closed")
		}
		passed := -1
		if oobn > 0 {
			scms, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				return nil, -1, err
			}
			for _, s := range scms {
				fds, err := unix.ParseUnixRights(&s)
				if err != nil {
					continue
				}
				for _, f := range fds {
					if passed < 0 {
						passed = f
					} else {
						unix.Close(f) // never accept more than one descriptor
					}
				}
			}
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			if passed >= 0 {
				unix.Close(passed)
			}
			return nil, -1, errors.New("truncated control message")
		}
		var m msg
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			if passed >= 0 {
				unix.Close(passed)
			}
			return nil, -1, err
		}
		return &m, passed, nil
	}
}
