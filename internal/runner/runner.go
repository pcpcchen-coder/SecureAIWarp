// Package runner orchestrates one run of the core in record, enforce or
// probe mode: it checks the manifest, plans the synthetic file system,
// starts the shell, wires the gates and writes ledger, trace and reports.
package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/gate"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/ledger"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/sandbox"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/state"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/watch"
	"golang.org/x/sys/unix"
)

type netConn = net.Conn

const rlimitNproc = unix.RLIMIT_NPROC

// Modes.
const (
	ModeRecord  = "record"
	ModeEnforce = "enforce"
	ModeProbe   = "probe"
)

// Shell-side paths.
const (
	ShellApp      = "/app"
	ShellData     = "/warp/data"
	ShellCache    = "/warp/cache"
	ShellPickBase = "/warp/pick"
	ShellBin      = "/warp/bin/warp"
	ProxyAddr     = "127.0.0.1:3128"
)

// Options for one run.
type Options struct {
	Mode         string
	AppRoot      string
	ManifestPath string
	Command      []string
	Picks        map[string]string
	PicksRW      map[string]bool // record only
	SecretNames  []string        // record only (in addition to manifest secrets)
	// IngressNotify, if set, receives every host URL opened by the ingress gate.
	IngressNotify func(innerPort int, url string)
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
}

// Result of a run.
type Result struct {
	ExitCode   int
	RunID      string
	LedgerPath string
	TracePath  string
	Denied     []ledger.Entry
	Ingress    []*gate.Ingress
}

type mount struct {
	varName string // ${APP_DATA} ...
	host    string
	shell   string
	rw      bool
}

type session struct {
	opt      Options
	appRoot  string
	loaded   *manifest.Loaded
	m        *manifest.Manifest
	runID    string
	appState string
	led      *ledger.Ledger
	mounts   []mount
	env      []string
	secrets  []gate.SecretBinding
	decoys   []gate.Decoy
	rules    []gate.Rule
	ca       *gate.CA
	cfg      *sandbox.Config
	cg       *sandbox.Cgroup
	rec      *evidence.Recorder
	shell    *sandbox.Shell
	egress   *gate.Egress
	ingress  []*gate.Ingress
	watcher  *watch.Watcher
	usage    *gate.Usage
	digest   string
	command  []string
	cleanups []func()
	extraBin bool

	res        resources
	resApplied []string
	planned    bool
	secretEnv  map[string]string

	mu       sync.Mutex
	denied   []ledger.Entry
	notified map[string]int
	stopPoll chan struct{}
}

func (s *session) errf(format string, a ...any) {
	fmt.Fprintf(s.opt.Stderr, "warp："+format+"\n", a...)
}

func newRunID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadAndLint loads a manifest and lints it against the app root.
func LoadAndLint(appRoot, path string) (*manifest.Loaded, *manifest.Result, error) {
	l, err := manifest.LoadFile(path)
	if err != nil {
		return nil, nil, err
	}
	key, err := state.TraceKey()
	if err != nil {
		return nil, nil, err
	}
	res := manifest.Lint(l.Manifest, manifest.Options{AppRoot: appRoot, TraceKey: key})
	return l, res, nil
}

// ResolveAppRoot returns the canonical app root after safety checks.
func ResolveAppRoot(p string) (string, error) {
	root, err := realAbs(p)
	if err != nil {
		return "", fmt.Errorf("應用目錄 %s：%w", p, err)
	}
	sr, err := state.Root()
	if err != nil {
		return "", err
	}
	if err := checkHostMount("應用目錄", root, []string{sr}); err != nil {
		return "", err
	}
	return root, nil
}

func prepare(opt Options) (*session, error) {
	s := &session{opt: opt, runID: newRunID(), notified: map[string]int{}, rec: nil}
	root, err := ResolveAppRoot(opt.AppRoot)
	if err != nil {
		return nil, err
	}
	s.appRoot = root
	if opt.ManifestPath == "" {
		opt.ManifestPath = filepath.Join(root, ".warp", "warp.yaml")
		s.opt.ManifestPath = opt.ManifestPath
	}
	if opt.Mode == ModeEnforce || opt.Mode == ModeProbe {
		l, res, err := LoadAndLint(root, opt.ManifestPath)
		if err != nil {
			return nil, err
		}
		if res.Errors() > 0 {
			var b strings.Builder
			for _, f := range res.Findings {
				if f.Level == manifest.LevelError {
					fmt.Fprintf(&b, "\n  ✖ [%s] %s：%s", f.Rule, f.Path, f.Message)
				}
			}
			return nil, fmt.Errorf("宣告未通過檢查（%d 個錯誤），拒絕執行：%s", res.Errors(), b.String())
		}
		s.loaded, s.m = l, l.Manifest
		if err := s.checkSupported(); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(opt.ManifestPath); err == nil {
		// Record mode reuses names (secrets, picks) from an existing manifest.
		if l, err := manifest.LoadFile(opt.ManifestPath); err == nil {
			s.loaded, s.m = l, l.Manifest
		}
	}
	name := filepath.Base(root)
	if s.m != nil && s.m.App.Name != "" {
		name = s.m.App.Name
	}
	if s.appState, err = state.AppDir(root, name); err != nil {
		return nil, err
	}
	if s.digest, err = manifest.ComputeDigest(root); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *session) checkSupported() error {
	m := s.m
	if m.Runtime.Isolation != "process" {
		return fmt.Errorf("宣告要求的隔離等級 %q 尚未支援（此核心只實作 process）；不會降級為較弱的隔離，拒絕執行", m.Runtime.Isolation)
	}
	for i, e := range m.Network.Egress {
		if e.Via == "ai-gate" {
			return fmt.Errorf("network.egress[%d] 要求經由 AI 閘門，但 AI 閘門尚未實作（第 2 期）；拒絕執行。若移除 via: ai-gate，此連線只受主機白名單控管，標籤會標示 AI 通道為「僅聲明」", i)
		}
	}
	for i, in := range m.Network.Ingress {
		if in.Expose != "loopback" {
			return fmt.Errorf("network.ingress[%d] 的開放範圍 %q 尚未支援；拒絕執行", i, in.Expose)
		}
	}
	return nil
}

func (s *session) addCleanup(f func()) { s.cleanups = append(s.cleanups, f) }

func (s *session) close() {
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}
	s.cleanups = nil
}

func (s *session) tempDir(prefix string) (string, error) {
	d, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", err
	}
	s.addCleanup(func() { os.RemoveAll(d) })
	return d, nil
}

// planMounts decides every writable or user-picked mount.
func (s *session) planMounts() error {
	mode := s.opt.Mode
	protect := []string{s.appRoot, filepath.Dir(s.appState)}
	if sr, err := state.Root(); err == nil {
		protect = append(protect, sr)
	}
	addPick := func(name, host string, rw bool) error {
		p, err := realAbs(host)
		if err != nil {
			return fmt.Errorf("USER_PICK %s：%w", name, err)
		}
		if err := checkHostMount("使用者選擇的資料夾 "+name, p, protect); err != nil {
			return err
		}
		for _, m := range s.mounts {
			if within(p, m.host) || within(m.host, p) {
				return fmt.Errorf("使用者選擇的資料夾 %s 與其他掛載重疊", name)
			}
		}
		s.mounts = append(s.mounts, mount{manifest.PickVar(name), p, ShellPickBase + "/" + name, rw})
		return nil
	}
	switch mode {
	case ModeRecord:
		d, err := s.tempDir("warp-rec-data-")
		if err != nil {
			return err
		}
		c, err := s.tempDir("warp-rec-cache-")
		if err != nil {
			return err
		}
		s.mounts = append(s.mounts, mount{manifest.VarAppData, d, ShellData, true}, mount{manifest.VarAppCache, c, ShellCache, true})
		names := sortedKeys(s.opt.Picks)
		for _, n := range names {
			if err := addPick(n, s.opt.Picks[n], s.opt.PicksRW[n]); err != nil {
				return err
			}
		}
	case ModeEnforce, ModeProbe:
		declared := map[string]bool{}
		for _, f := range s.m.Files {
			kind, pick, _ := manifest.PathVar(f.Path)
			rw := f.Mode == "rw"
			switch kind {
			case "APP_DATA", "APP_CACHE":
				var host string
				if mode == ModeProbe {
					d, err := s.tempDir("warp-probe-" + strings.ToLower(kind) + "-")
					if err != nil {
						return err
					}
					host = d
				} else {
					host = filepath.Join(s.appState, map[string]string{"APP_DATA": "data", "APP_CACHE": "cache"}[kind])
					if err := os.MkdirAll(host, 0o700); err != nil {
						return err
					}
				}
				shellPath := ShellData
				if kind == "APP_CACHE" {
					shellPath = ShellCache
				}
				s.mounts = append(s.mounts, mount{f.Path, host, shellPath, rw})
			case "USER_PICK":
				declared[pick] = true
				host := s.opt.Picks[pick]
				if mode == ModeProbe {
					d, err := s.tempDir("warp-probe-pick-")
					if err != nil {
						return err
					}
					os.WriteFile(filepath.Join(d, "sample.txt"), []byte("synthetic probe data\n"), 0o644)
					host = d
				}
				if host == "" {
					return fmt.Errorf("宣告需要使用者選擇的資料夾 %q：請以 --pick %s=<資料夾> 指定", pick, pick)
				}
				if err := addPick(pick, host, rw); err != nil {
					return err
				}
			}
		}
		for n := range s.opt.Picks {
			if !declared[n] {
				return fmt.Errorf("--pick %s 不在宣告中；只能掛載宣告過的資料夾", n)
			}
		}
		if mode == ModeProbe {
			// The probe needs a writable scratch area for its own report even
			// when the manifest declares no APP_DATA.
			has := false
			for _, m := range s.mounts {
				if m.shell == ShellData {
					has = true
					if !m.rw {
						return errors.New("探測需要可寫的 APP_DATA；宣告中的 ${APP_DATA} 為唯讀")
					}
				}
			}
			if !has {
				d, err := s.tempDir("warp-probe-data-")
				if err != nil {
					return err
				}
				s.mounts = append(s.mounts, mount{manifest.VarAppData, d, ShellData, true})
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *session) hostDir(shellPath string) string {
	for _, m := range s.mounts {
		if m.shell == shellPath {
			return m.host
		}
	}
	return ""
}

// planSecrets fills env placeholders, gate bindings and decoys.
func (s *session) planSecrets() (map[string]string, error) {
	env := map[string]string{}
	switch s.opt.Mode {
	case ModeRecord:
		names := map[string]bool{}
		for _, n := range s.opt.SecretNames {
			names[n] = true
		}
		if s.m != nil {
			for _, sec := range s.m.Secrets {
				names[sec.Name] = true
			}
		}
		for n := range names {
			v := "warp-decoy-" + strings.ToLower(n) + "-" + randHex(8)
			s.decoys = append(s.decoys, gate.Decoy{Name: n, Value: v})
			env[n] = v
		}
	case ModeEnforce, ModeProbe:
		for _, sec := range s.m.Secrets {
			var real string
			if s.opt.Mode == ModeProbe {
				real = "warp-canary-" + randHex(16)
			} else {
				real = os.Getenv(sec.Name)
				if real == "" {
					return nil, fmt.Errorf("需要機密 %s 的真值：請在執行 warp 的主機環境變數中提供 %s（它不會進入殼內）", sec.Name, sec.Name)
				}
			}
			if sec.Visibility == "app-visible" {
				env[sec.Name] = real
				continue
			}
			ph := "warp-placeholder-" + strings.ToLower(sec.Name) + "-" + randHex(8)
			env[sec.Name] = ph
			s.secrets = append(s.secrets, gate.SecretBinding{Name: sec.Name, Host: sec.Bind.Host, Header: sec.Bind.Inject.Header, Placeholder: ph, Real: real})
		}
		for i, e := range s.m.Network.Egress {
			r := gate.Rule{Host: e.Host, Port: e.Port, LAN: e.LAN, Grant: manifest.GrantRef(manifest.GrantEgress, i)}
			if e.Limits != nil && e.Limits.UploadPerDay != "" {
				r.UploadLimit, _ = manifest.ParseSize(e.Limits.UploadPerDay)
			}
			s.rules = append(s.rules, r)
		}
	}
	return env, nil
}

var hostCABundles = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"}

var etcCopy = []string{"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime",
	"/etc/timezone", "/etc/alternatives", "/etc/ssl/openssl.cnf", "/etc/mime.types", "/etc/protocols",
	"/etc/services", "/etc/os-release", "/etc/gai.conf"}

var shellSystemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

func (s *session) buildConfig(secretEnv map[string]string) error {
	stage, err := s.tempDir("warp-etc-")
	if err != nil {
		return err
	}
	write := func(name, content string) (string, error) {
		p := filepath.Join(stage, name)
		return p, os.WriteFile(p, []byte(content), 0o644)
	}
	gen := map[string]string{}
	files := map[string]string{
		"/etc/passwd":        "app:x:0:0:app:" + ShellData + ":/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		"/etc/group":         "app:x:0:\nnogroup:x:65534:\n",
		"/etc/hosts":         "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
		"/etc/resolv.conf":   "# SecureAIWarp: the shell has no resolver; all names are resolved by the egress gate.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
		"/etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files dns\n",
		"/etc/hostname":      "warp-shell\n",
	}
	for inner, content := range files {
		p, err := write(strings.TrimPrefix(strings.ReplaceAll(inner, "/", "_"), "_"), content)
		if err != nil {
			return err
		}
		gen[inner] = p
	}
	var bundle []byte
	for _, b := range hostCABundles {
		if data, err := os.ReadFile(b); err == nil {
			bundle = data
			break
		}
	}
	if s.ca != nil {
		bundle = append(bundle, '\n')
		bundle = append(bundle, s.ca.CertPEM()...)
	}
	bp, err := write("ca-bundle.crt", string(bundle))
	if err != nil {
		return err
	}
	for _, inner := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt"} {
		gen[inner] = bp
	}
	const bundlePath = "/etc/ssl/certs/ca-certificates.crt"
	env := map[string]string{
		"PATH":                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":                    "/tmp",
		"USER":                    "app",
		"LOGNAME":                 "app",
		"LANG":                    "C.UTF-8",
		"TMPDIR":                  "/tmp",
		"HTTP_PROXY":              "http://" + ProxyAddr,
		"HTTPS_PROXY":             "http://" + ProxyAddr,
		"http_proxy":              "http://" + ProxyAddr,
		"https_proxy":             "http://" + ProxyAddr,
		"NO_PROXY":                "",
		"no_proxy":                "",
		"SSL_CERT_FILE":           bundlePath,
		"REQUESTS_CA_BUNDLE":      bundlePath,
		"CURL_CA_BUNDLE":          bundlePath,
		"NODE_EXTRA_CA_CERTS":     bundlePath,
		"PIP_CERT":                bundlePath,
		"GIT_SSL_CAINFO":          bundlePath,
		"PYTHONDONTWRITEBYTECODE": "1",
	}
	if t := os.Getenv("TERM"); t != "" {
		env["TERM"] = t
	}
	var binds []sandbox.Bind
	for _, m := range s.mounts {
		binds = append(binds, sandbox.Bind{Source: m.host, Target: m.shell, Writable: m.rw})
		switch {
		case m.shell == ShellData:
			env["APP_DATA"] = ShellData
			env["HOME"] = ShellData
		case m.shell == ShellCache:
			env["APP_CACHE"] = ShellCache
			env["XDG_CACHE_HOME"] = ShellCache
		case strings.HasPrefix(m.shell, ShellPickBase+"/"):
			n := strings.TrimPrefix(m.shell, ShellPickBase+"/")
			env["WARP_PICK_"+strings.ToUpper(strings.ReplaceAll(n, "-", "_"))] = m.shell
		}
	}
	if s.extraBin {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		binds = append(binds, sandbox.Bind{Source: self, Target: ShellBin})
	}
	for k, v := range secretEnv {
		env[k] = v
	}
	var envList []string
	for k, v := range env {
		envList = append(envList, k+"="+v)
	}
	sort.Strings(envList)

	res := s.resources()
	rootDir, err := s.tempDir("warp-root-")
	if err != nil {
		return err
	}
	s.cg = sandbox.NewCgroup("warp-"+s.runID, res.mem, res.pids)
	s.addCleanup(s.cg.Remove)
	rl := []sandbox.Rlimit{
		{Resource: syscall.RLIMIT_FSIZE, Cur: uint64(res.disk), Max: uint64(res.disk)},
		{Resource: syscall.RLIMIT_CORE, Cur: 0, Max: 0},
	}
	applied := append([]string{}, s.cg.Applied...)
	applied = append(applied, fmt.Sprintf("單檔大小 %s（RLIMIT_FSIZE）", human(res.disk)), fmt.Sprintf("/tmp 容量 %s", human(res.disk)))
	if !s.cg.Has("pids") {
		rl = append(rl, sandbox.Rlimit{Resource: rlimitNproc, Cur: uint64(res.pids), Max: uint64(res.pids)})
		if os.Getuid() == 0 {
			s.errf("警告：無法建立 pids cgroup，而以 root 執行時核心不套用 RLIMIT_NPROC——程序數上限此次無法強制")
		} else {
			applied = append(applied, fmt.Sprintf("程序數 %d（RLIMIT_NPROC）", res.pids))
		}
	}
	if !s.cg.Has("memory") {
		rl = append(rl, sandbox.Rlimit{Resource: syscall.RLIMIT_AS, Cur: uint64(res.mem), Max: uint64(res.mem)})
		applied = append(applied, fmt.Sprintf("虛擬記憶體 %s（RLIMIT_AS）", human(res.mem)))
	}
	s.resApplied = applied
	s.res = res

	cwd := ShellApp
	s.cfg = &sandbox.Config{
		RootDir:    rootDir,
		AppRoot:    s.appRoot,
		AppTarget:  ShellApp,
		Hide:       manifest.HiddenAppEntries,
		SystemDirs: shellSystemDirs,
		EtcCopy:    etcCopy,
		Generated:  gen,
		Binds:      binds,
		Env:        envList,
		Argv:       s.command,
		Cwd:        cwd,
		ProxyPort:  manifest.ReservedShellPort,
		TmpSize:    res.disk,
		Rlimits:    rl,
		Hostname:   "warp-shell",
	}
	return nil
}

type resources struct {
	mem  int64
	pids int
	disk int64
}

func (s *session) resources() resources {
	r := resources{}
	r.mem, _ = manifest.ParseSize(manifest.DefaultMemory)
	r.pids = manifest.DefaultPids
	r.disk, _ = manifest.ParseSize(manifest.DefaultDisk)
	if s.m != nil {
		rr := s.m.Runtime.Resources
		if v, err := manifest.ParseSize(rr.Memory); err == nil {
			r.mem = v
		}
		if rr.Pids > 0 {
			r.pids = rr.Pids
		}
		if v, err := manifest.ParseSize(rr.Disk); err == nil {
			r.disk = v
		}
	}
	return r
}

func human(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dGi", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMi", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKi", n>>10)
	}
	return fmt.Sprintf("%d", n)
}

func (s *session) notify(msg string) {
	s.mu.Lock()
	s.notified[msg]++
	n := s.notified[msg]
	s.mu.Unlock()
	if n == 1 {
		s.errf("%s", msg)
	}
}

// plan decides mounts and secrets once.
func (s *session) plan() error {
	if err := s.planMounts(); err != nil {
		return err
	}
	env, err := s.planSecrets()
	if err != nil {
		return err
	}
	s.secretEnv, s.planned = env, true
	return nil
}

// start brings up everything and launches the app.
func (s *session) start() error {
	var err error
	if s.command == nil {
		s.command = s.opt.Command
		if len(s.command) == 0 && s.m != nil {
			s.command = s.m.App.Entry
		}
	}
	if len(s.command) == 0 {
		return errors.New("沒有要執行的指令：請在 -- 之後提供指令，或在宣告的 app.entry 中設定")
	}
	if !s.planned {
		if err := s.plan(); err != nil {
			return err
		}
	}
	switch s.opt.Mode {
	case ModeRecord:
		if s.ca, err = gate.NewCA(s.runID, nil); err != nil {
			return err
		}
	default:
		var hosts []string
		for _, b := range s.secrets {
			hosts = append(hosts, b.Host)
		}
		if len(hosts) > 0 {
			if s.ca, err = gate.NewCA(s.runID, hosts); err != nil {
				return err
			}
		}
	}
	if err := s.buildConfig(s.secretEnv); err != nil {
		return err
	}
	if s.led, err = ledger.Open(filepath.Join(s.appState, "ledger.jsonl"), s.runID, s.opt.Mode); err != nil {
		return err
	}
	s.addCleanup(func() { s.led.Close() })
	s.led.OnAppend = func(e ledger.Entry) {
		if e.Decision == "deny" {
			s.mu.Lock()
			s.denied = append(s.denied, e)
			s.mu.Unlock()
		}
	}
	mf := ""
	if s.loaded != nil {
		mf = s.loaded.SHA256
	}
	if err := s.led.Append(ledger.Entry{Channel: "run", Action: "start", Decision: "info", Target: strings.Join(s.command, " "),
		Detail: fmt.Sprintf("app_digest=%s manifest_sha256=%s", s.digest, mf)}); err != nil {
		return fmt.Errorf("稽核帳本無法寫入，拒絕執行：%w", err)
	}
	resolver, err := gate.NewResolver()
	if err != nil {
		return err
	}
	if s.opt.Mode == ModeRecord {
		s.rec = evidence.NewRecorder()
	}
	s.usage = gate.OpenUsage(s.appState)
	s.addCleanup(s.usage.Flush)
	gmode := gate.ModeEnforce
	if s.opt.Mode == ModeRecord {
		gmode = gate.ModeRecord
	}
	s.egress = gate.NewEgress(gate.EgressConfig{
		Mode: gmode, Rules: s.rules, Secrets: s.secrets, Decoys: s.decoys, CA: s.ca,
		Resolver: resolver, Ledger: s.led, Recorder: s.rec, Usage: s.usage, Notify: s.notify,
	})
	s.shell, err = sandbox.Start(s.cfg, s.cg, sandbox.Stdio{Stdin: s.opt.Stdin, Stdout: s.opt.Stdout, Stderr: s.opt.Stderr})
	if err != nil {
		return err
	}
	s.addCleanup(func() {
		s.shell.Kill()
		s.shell.Wait()
		s.mu.Lock()
		igs := append([]*gate.Ingress{}, s.ingress...)
		s.mu.Unlock()
		for _, ig := range igs {
			ig.Close()
		}
	})
	go s.egress.Serve(s.shell.EgressListener())
	s.addCleanup(func() { s.shell.EgressListener().Close(); s.egress.Close() })
	dial := func(port int) (netConn, error) { return s.shell.DialApp(port, 5*time.Second) }
	if s.m != nil && s.opt.Mode != ModeRecord {
		for _, in := range s.m.Network.Ingress {
			ig, err := gate.StartIngress(in.Listen, in.Listen, gate.NewToken(), dial, s.led, s.notify)
			if err != nil {
				return fmt.Errorf("無法啟動對內閘門：%w", err)
			}
			s.ingress = append(s.ingress, ig)
			if s.opt.Mode == ModeEnforce {
				s.errf("對內閘門：殼內 %d 埠只在本機開放，請用此網址（含一次性權杖）：%s", in.Listen, ig.URL())
				if s.opt.IngressNotify != nil {
					s.opt.IngressNotify(in.Listen, ig.URL())
				}
			}
		}
	}
	if s.opt.Mode == ModeRecord {
		s.stopPoll = make(chan struct{})
		go s.pollListeners(dial)
	}
	if s.opt.Mode == ModeRecord {
		// Watch only after the shell's mounts are complete, so the setup
		// itself is never recorded as app behaviour.
		var roots []watch.Root
		for _, m := range s.mounts {
			roots = append(roots, watch.Root{Var: m.varName, Dir: m.host})
		}
		if s.watcher, err = watch.Start(roots, s.rec); err != nil {
			return fmt.Errorf("無法啟動檔案側錄：%w", err)
		}
	}
	for _, a := range s.resApplied {
		s.led.Log("process", "limit", "info", "", a)
	}
	if err := s.shell.Run(); err != nil {
		return err
	}
	return nil
}

func (s *session) forwardSignals() func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		n := 0
		for {
			select {
			case sig := <-ch:
				n++
				if n > 1 {
					s.shell.Kill()
				} else {
					s.shell.Signal(sig.(syscall.Signal))
				}
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}

func (s *session) finish() (*Result, error) {
	code, werr := s.shell.Wait()
	if s.stopPoll != nil {
		close(s.stopPoll)
	}
	if s.watcher != nil {
		s.watcher.Stop()
	}
	s.led.Log("run", "exit", "info", "", fmt.Sprintf("exit_code=%d", code))
	res := &Result{ExitCode: code, RunID: s.runID, LedgerPath: s.led.Path(), Ingress: s.ingress}
	s.mu.Lock()
	res.Denied = append(res.Denied, s.denied...)
	s.mu.Unlock()
	if werr != nil {
		return res, werr
	}
	if s.opt.Mode == ModeRecord {
		s.rec.Add(evidence.Event{Channel: evidence.ChanProcess, Exe: strings.Join(s.command, " ")})
		p, id, err := evidence.NextPath(filepath.Join(s.appRoot, ".warp", "evidence"))
		if err != nil {
			return res, err
		}
		key, err := state.TraceKey()
		if err != nil {
			return res, err
		}
		t := &evidence.Trace{Format: evidence.Format, ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Command: s.command, AppDigest: s.digest, ExitCode: code, Events: s.rec.Events()}
		if err := evidence.Write(p, t, key); err != nil {
			return res, err
		}
		res.TracePath = p
	}
	if s.opt.Mode == ModeEnforce {
		_ = report.WriteEnforce(s.appRoot, &report.Enforce{ManifestSHA256: s.loaded.SHA256, AppDigest: s.digest, Command: s.command, ExitCode: code, Denied: len(res.Denied)})
	}
	return res, nil
}

// Run executes one record or enforce run.
func Run(opt Options) (*Result, error) {
	if opt.Stdin == nil {
		opt.Stdin = os.Stdin
	}
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.Mode != ModeRecord && opt.Mode != ModeEnforce {
		return nil, fmt.Errorf("未知的模式 %q", opt.Mode)
	}
	s, err := prepare(opt)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if opt.Mode == ModeRecord {
		s.errf("側錄模式：應用在拋棄式環境中執行；機密為誘餌值，請只使用合成資料。")
	}
	if err := s.start(); err != nil {
		return nil, err
	}
	stop := s.forwardSignals()
	defer stop()
	res, err := s.finish()
	if err == nil {
		s.summary(res)
	}
	return res, err
}

func (s *session) summary(res *Result) {
	if len(res.Denied) > 0 {
		s.errf("本次執行共阻擋 %d 次越界行為（詳見稽核帳本 %s）", len(res.Denied), res.LedgerPath)
	}
	if res.TracePath != "" {
		rel, _ := filepath.Rel(s.appRoot, res.TracePath)
		s.errf("側錄紀錄已寫入 %s", rel)
	}
}
