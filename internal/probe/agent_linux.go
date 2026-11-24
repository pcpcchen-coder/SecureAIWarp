//go:build linux

package probe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
	"golang.org/x/sys/unix"
)

// RunHidden dispatches the in-shell probe entry points.
func RunHidden(arg string, args []string) int {
	switch arg {
	case AgentArg:
		if len(args) != 1 {
			return 2
		}
		return runAgent(args[0])
	case NestedArg:
		return nestedRemount()
	case SleepArg:
		time.Sleep(60 * time.Second)
		return 0
	case MemArg:
		if len(args) != 1 {
			return 2
		}
		n, _ := strconv.ParseInt(args[0], 10, 64)
		return allocate(n)
	}
	return 2
}

type agent struct {
	a     *Args
	items []report.ProbeItem
}

func (g *agent) add(id, cat, name, status, detail string) {
	g.items = append(g.items, report.ProbeItem{ID: id, Category: cat, Name: name, Status: status, Detail: detail})
}

func blockedIf(ok bool) string {
	if ok {
		return report.Blocked
	}
	return report.Penetrated
}

func runAgent(argsPath string) int {
	b, err := os.ReadFile(argsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: cannot read args:", err)
		return 2
	}
	var a Args
	if err := json.Unmarshal(b, &a); err != nil {
		return 2
	}
	signal.Ignore(syscall.SIGXFSZ)
	g := &agent{a: &a}
	stopIngress := g.startIngress()
	g.files()
	g.mounts()
	g.network()
	g.dns()
	g.secrets()
	g.process()
	g.resources()
	stopIngress()
	g.add("spawn.unlisted", "程序", "執行宣告外的程式", report.NotImplemented, "spawn 限制屬於僅聲明")
	g.add("data.decoy-marker", "資料", "經允許主機送出誘餌標記", report.NotImplemented, "資料閘門屬於第 2 期")
	g.add("ai.budget", "AI", "超過 AI 花費上限", report.NotImplemented, "AI 閘門屬於第 2 期")
	out, _ := json.MarshalIndent(g.items, "", "  ")
	if err := os.WriteFile(a.ResultFile, out, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "probe: cannot write results:", err)
		return 2
	}
	return 0
}

func (g *agent) files() {
	for _, p := range g.a.ReadPaths {
		_, err := os.ReadFile(p)
		g.add("file.read:"+p, "檔案", "讀取殼外檔案 "+p, blockedIf(err != nil), errText(err))
	}
	for _, d := range g.a.ListDirs {
		_, err := os.ReadDir(d)
		g.add("file.list:"+d, "檔案", "列出殼外資料夾 "+d, blockedIf(err != nil), errText(err))
	}
	for _, p := range g.a.WritePaths {
		err := os.WriteFile(p, []byte("written by warp probe\n"), 0o644)
		if err == nil {
			os.Remove(p)
		}
		g.add("file.write:"+p, "檔案", "寫入殼外或唯讀位置 "+p, blockedIf(err != nil), errText(err))
	}
	for _, p := range g.a.DeletePaths {
		err := os.Remove(p)
		g.add("file.delete:"+p, "檔案", "刪除殼外檔案 "+p, blockedIf(err != nil), errText(err))
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"} {
		_, err := os.Stat(p)
		g.add("file.control-socket:"+p, "檔案", "存取容器控制介面 "+p, blockedIf(err != nil), errText(err))
	}
	_, err := os.Stat("/sys/kernel")
	g.add("file.sysfs", "檔案", "存取 /sys", blockedIf(err != nil), errText(err))
}

func (g *agent) mounts() {
	err := unix.Mount("", "/app", "", unix.MS_REMOUNT|unix.MS_BIND, "")
	g.add("fs.remount-app", "檔案", "把唯讀的應用目錄重新掛載為可寫", blockedIf(err != nil), errText(err))
	err = unix.Mount("tmpfs", "/tmp", "tmpfs", 0, "")
	g.add("fs.mount", "檔案", "在殼內掛載新的檔案系統", blockedIf(err != nil), errText(err))
	// Escalation attempt: a nested user namespace gives full capabilities
	// over a new mount namespace; the inherited mounts must stay locked.
	// Try with an ID mapping first; if the kernel refuses the mapping, try
	// an unmapped nested namespace (which still holds every capability
	// inside that namespace).
	cmd := exec.Command(g.a.Self, NestedArg)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	mapped := "有 ID 對應"
	if err != nil && cmd.ProcessState == nil {
		cmd = exec.Command(g.a.Self, NestedArg)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS}
		out, err = cmd.CombinedOutput()
		mapped = "無 ID 對應"
	}
	detail := mapped + "：" + strings.TrimSpace(string(out))
	switch {
	case err != nil && cmd.ProcessState == nil:
		g.add("fs.nested-userns", "檔案", "以巢狀使用者命名空間解除唯讀掛載", report.Blocked, "無法建立巢狀命名空間："+err.Error())
	case cmd.ProcessState.ExitCode() == 0:
		g.add("fs.nested-userns", "檔案", "以巢狀使用者命名空間解除唯讀掛載", report.Blocked, detail)
	case cmd.ProcessState.ExitCode() == 1:
		g.add("fs.nested-userns", "檔案", "以巢狀使用者命名空間解除唯讀掛載", report.Penetrated, detail)
	default:
		g.add("fs.nested-userns", "檔案", "以巢狀使用者命名空間解除唯讀掛載", report.Error, detail)
	}
}

// nestedRemount runs inside a nested user+mount namespace with full
// capabilities there. Exit 0 = still read-only, 1 = escaped.
func nestedRemount() int {
	errA := unix.Mount("", "/app", "", unix.MS_REMOUNT|unix.MS_BIND, "")
	errB := os.WriteFile("/app/.warp-probe-nested", []byte("x"), 0o644)
	errC := unix.Unmount("/app", unix.MNT_DETACH)
	if errB == nil {
		os.Remove("/app/.warp-probe-nested")
		fmt.Printf("可寫入 /app（remount: %v）", errA)
		return 1
	}
	fmt.Printf("remount: %v；write: %v；umount: %v", errA, errB, errC)
	return 0
}

func readProxyResponse(c net.Conn) (int, http.Header, error) {
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, nil, err
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header, nil
}

func (g *agent) network() {
	for _, t := range g.a.ProxyDenyTargets {
		status, hdr, err := func() (int, http.Header, error) {
			c, err := net.DialTimeout("tcp", g.a.ProxyAddr, 5*time.Second)
			if err != nil {
				return 0, nil, err
			}
			defer c.Close()
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", t, t)
			return readProxyResponse(c)
		}()
		g.proxyItem("net.connect:"+t, "經由閘門連往 "+t, status, hdr, err)
	}
	for _, u := range g.a.ProxyDenyURLs {
		status, hdr, err := func() (int, http.Header, error) {
			c, err := net.DialTimeout("tcp", g.a.ProxyAddr, 5*time.Second)
			if err != nil {
				return 0, nil, err
			}
			defer c.Close()
			host := strings.SplitN(strings.TrimPrefix(u, "http://"), "/", 2)[0]
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u, host)
			return readProxyResponse(c)
		}()
		g.proxyItem("net.http:"+u, "經由閘門請求 "+u, status, hdr, err)
	}
	for _, t := range g.a.DirectTargets {
		c, err := net.DialTimeout("tcp", t, 3*time.Second)
		if err == nil {
			c.Close()
		}
		g.add("net.direct:"+t, "對外", "不經閘門直接連線 "+t, blockedIf(err != nil), errText(err))
	}
	// Raw UDP (e.g. DNS) straight to the Internet.
	err := func() error {
		c, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		if _, err := c.Write(q); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		_, err = c.Read(buf)
		return err
	}()
	g.add("net.udp", "對外", "直接送出 UDP 封包（8.8.8.8:53）", blockedIf(err != nil), errText(err))
}

func (g *agent) proxyItem(id, name string, status int, hdr http.Header, err error) {
	switch {
	case err != nil:
		// A connection error to the gate itself is not proof of blocking.
		g.add(id, "對外", name, report.Error, errText(err))
	case status == http.StatusForbidden && hdr.Get("X-Warp-Blocked") != "":
		g.add(id, "對外", name, report.Blocked, fmt.Sprintf("HTTP %d", status))
	default:
		g.add(id, "對外", name, report.Penetrated, fmt.Sprintf("閘門回應 HTTP %d", status))
	}
}

func (g *agent) dns() {
	for _, n := range g.a.DNSNames {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(ctx, n)
		cancel()
		g.add("dns.lookup:"+n, "DNS", "殼內自行解析 "+n, blockedIf(err != nil), errText(err)+strings.Join(addrs, ","))
	}
	// Direct query to the configured (loopback) resolver address.
	err := func() error {
		c, err := net.DialTimeout("udp", "127.0.0.1:53", time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		c.Write([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 512))
		return err
	}()
	g.add("dns.loopback", "DNS", "向殼內 127.0.0.1:53 查詢", blockedIf(err != nil), errText(err))
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (g *agent) secrets() {
	canary := map[string]bool{}
	for _, h := range g.a.CanaryHashes {
		canary[h] = true
	}
	for _, n := range g.a.SecretEnv {
		v := os.Getenv(n)
		switch {
		case v == "":
			g.add("secret.env:"+n, "機密", "環境變數 "+n+" 只含佔位值", report.Error, "殼內沒有這個環境變數")
		case canary[hashHex(v)]:
			g.add("secret.env:"+n, "機密", "環境變數 "+n+" 只含佔位值", report.Penetrated, "看到真值")
		default:
			g.add("secret.env:"+n, "機密", "環境變數 "+n+" 只含佔位值", report.Blocked, "")
		}
	}
	// Search every environment and cmdline visible in the shell.
	found := ""
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		for _, f := range []string{"environ", "cmdline"} {
			b, err := os.ReadFile(filepath.Join("/proc", e.Name(), f))
			if err != nil {
				continue
			}
			for _, part := range strings.Split(string(b), "\x00") {
				v := part
				if i := strings.IndexByte(part, '='); i >= 0 {
					v = part[i+1:]
				}
				if canary[hashHex(v)] || canary[hashHex(part)] {
					found = e.Name() + "/" + f
				}
			}
		}
	}
	g.add("secret.proc", "機密", "從殼內任何程序的環境或參數找出真值", blockedIf(found == ""), found)
	_, err := os.ReadFile("/proc/1/environ")
	g.add("secret.init-environ", "機密", "讀取殼的 init 程序環境", blockedIf(err != nil), errText(err))
}

func (g *agent) process() {
	err := unix.PtraceAttach(1)
	if err == nil {
		unix.PtraceDetach(1)
	}
	g.add("proc.ptrace-init", "程序", "追蹤（ptrace）殼的 init 程序", blockedIf(err != nil), errText(err))
	var caps unix.CapUserData
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	_ = unix.Capget(&hdr, &data[0])
	caps = data[0]
	any := caps.Effective|caps.Permitted|data[1].Effective|data[1].Permitted != 0
	g.add("proc.capabilities", "程序", "殼內程序持有特權（capabilities）", blockedIf(!any), fmt.Sprintf("eff=%x prm=%x", caps.Effective, caps.Permitted))
	err = unix.Sethostname([]byte("pwned"))
	g.add("proc.sethostname", "程序", "修改主機名稱", blockedIf(err != nil), errText(err))
}

func (g *agent) resources() {
	// Memory: a child tries to touch more than the limit.
	if g.a.MemLimit > 0 {
		cmd := exec.Command(g.a.Self, MemArg, strconv.FormatInt(g.a.MemLimit+(128<<20), 10))
		out, err := cmd.CombinedOutput()
		ok := err != nil
		g.add("res.memory", "資源", fmt.Sprintf("超用記憶體（上限 %d MiB）", g.a.MemLimit>>20), blockedIf(ok), strings.TrimSpace(string(out))+" "+errText(err))
	}
	// Processes: spawn until refused.
	if g.a.PidsLimit > 0 {
		sleeper := g.a.Self
		args := []string{g.a.Self, SleepArg}
		if _, err := os.Stat("/bin/sleep"); err == nil {
			sleeper, args = "/bin/sleep", []string{"sleep", "60"}
		}
		var pids []int
		var ferr error
		for i := 0; i < g.a.PidsLimit+32; i++ {
			pid, err := syscall.ForkExec(sleeper, args, &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
			if err != nil {
				ferr = err
				break
			}
			pids = append(pids, pid)
		}
		for _, p := range pids {
			unix.Kill(p, unix.SIGKILL)
		}
		for range pids {
			var ws unix.WaitStatus
			unix.Wait4(-1, &ws, 0, nil)
		}
		g.add("res.pids", "資源", fmt.Sprintf("建立過多程序（上限 %d）", g.a.PidsLimit), blockedIf(ferr != nil), fmt.Sprintf("建立了 %d 個後被拒：%v", len(pids), ferr))
	}
	// Disk: one file larger than the limit.
	if g.a.DiskLimit > 0 {
		p := filepath.Join(g.a.DataDir, ".warp-probe-big")
		err := func() error {
			f, err := os.Create(p)
			if err != nil {
				return err
			}
			defer f.Close()
			chunk := make([]byte, 4<<20)
			var written int64
			for written <= g.a.DiskLimit {
				n, err := f.Write(chunk)
				written += int64(n)
				if err != nil {
					return err
				}
			}
			return nil
		}()
		os.Remove(p)
		g.add("res.disk", "資源", fmt.Sprintf("寫入超過磁碟上限的檔案（上限 %d MiB）", g.a.DiskLimit>>20), blockedIf(err != nil), errText(err))
	}
}

// allocate touches n bytes of anonymous memory. Exit 0 means it succeeded.
func allocate(n int64) int {
	const chunk = 16 << 20
	var total int64
	var keep [][]byte
	for total < n {
		b, err := unix.Mmap(-1, 0, chunk, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
		if err != nil {
			fmt.Printf("配置 %d MiB 後失敗：%v", total>>20, err)
			return 3
		}
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		keep = append(keep, b)
		total += chunk
	}
	fmt.Printf("成功配置 %d MiB", total>>20)
	return 0
}

func (g *agent) startIngress() func() {
	if len(g.a.IngressPorts) == 0 {
		return func() {}
	}
	var srvs []*http.Server
	for _, p := range g.a.IngressPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			g.add(fmt.Sprintf("ingress.listen:%d", p), "對內", fmt.Sprintf("在殼內監聽 %d 埠", p), report.Error, err.Error())
			continue
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, g.a.IngressMarker)
		})}
		go srv.Serve(ln)
		srvs = append(srvs, srv)
	}
	os.WriteFile(g.a.ReadyFile, []byte("ready"), 0o600)
	return func() {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(g.a.DoneFile); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		for _, s := range srvs {
			s.Close()
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
