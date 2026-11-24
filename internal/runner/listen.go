package runner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/gate"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

// listeningPorts parses /proc/<pid>/net/tcp{,6}, which describe the
// network namespace of that process (the shell's), and returns LISTEN ports.
func listeningPorts(pid int) map[int]bool {
	out := map[int]bool{}
	for _, f := range []string{"tcp", "tcp6"} {
		fh, err := os.Open(fmt.Sprintf("/proc/%d/net/%s", pid, f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			i := strings.LastIndexByte(fields[1], ':')
			if i < 0 {
				continue
			}
			if p, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil {
				out[int(p)] = true
			}
		}
		fh.Close()
	}
	return out
}

// pollListeners (record mode) notices ports the app listens on, records
// them as ingress evidence and exposes each on the host loopback with a
// one-time token so the operator or agent can exercise the app.
func (s *session) pollListeners(dial func(int) (netConn, error)) {
	seen := map[int]bool{manifest.ReservedShellPort: true}
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.stopPoll:
			return
		case <-t.C:
		}
		for p := range listeningPorts(s.shell.InitPid()) {
			if seen[p] {
				continue
			}
			seen[p] = true
			s.rec.Add(evidence.Event{Channel: evidence.ChanIngress, Port: p})
			s.led.Log("ingress", "listen", "info", strconv.Itoa(p), "側錄：應用在殼內監聽此埠")
			ig, err := gate.StartIngress(p, p, gate.NewToken(), dial, s.led, s.notify)
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.ingress = append(s.ingress, ig)
			s.mu.Unlock()
			s.errf("側錄：應用在殼內監聽 %d 埠；可由 %s 操作", p, ig.URL())
			if s.opt.IngressNotify != nil {
				s.opt.IngressNotify(p, ig.URL())
			}
		}
	}
}
