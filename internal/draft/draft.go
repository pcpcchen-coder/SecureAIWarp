// Package draft derives a first-cut manifest from record-mode traces. Every
// observed behaviour becomes the narrowest grant with an evidence pointer;
// purposes are left as placeholders that lint rejects until a person or
// agent writes them.
package draft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

// PurposePlaceholder is rejected by lint.
const PurposePlaceholder = "（待填寫：用一句人話說明用途）"

// Draft is the generated manifest.
type Draft struct {
	Manifest *manifest.Manifest
	YAML     []byte
	Notes    []string
}

type seen struct {
	trace   string
	trigger string
	write   bool
}

// Options tune FromDir.
type Options struct {
	// IncludeFailed also uses traces whose command exited with a non-zero
	// code (other than an interrupt). By default they are left out.
	IncludeFailed bool
}

// interrupted reports exit codes of a command stopped by SIGINT (Ctrl+C)
// or SIGTERM, the normal way to stop a server; such traces are used.
func interrupted(code int) bool { return code == 130 || code == 143 }

// FromDir builds a draft from every valid trace in dir.
func FromDir(appRoot, dir string, key []byte) (*Draft, error) {
	return FromDirWith(appRoot, dir, key, Options{})
}

// FromDirWith builds a draft from the valid traces in dir.
func FromDirWith(appRoot, dir string, key []byte, opt Options) (*Draft, error) {
	paths, err := evidence.ListTraces(dir)
	if err != nil {
		return nil, fmt.Errorf("無法讀取側錄目錄：%w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s 中沒有側錄紀錄；請先執行 warp record", dir)
	}
	d := &Draft{}
	files := map[string]*seen{}
	egress := map[string]*seen{}
	blocked := map[string]string{}
	ingress := map[int]*seen{}
	type secretKey struct{ name, host, header string }
	secrets := map[secretKey]*seen{}
	visibleOnly := map[string]string{}
	digest, err := manifest.ComputeDigest(appRoot)
	if err != nil {
		return nil, err
	}
	var lastCmd []string
	lastTrace := ""
	var failed []string
	listenCmds := map[int][]string{}
	for _, p := range paths {
		t, err := evidence.Load(p, key)
		if err != nil {
			d.Notes = append(d.Notes, fmt.Sprintf("略過 %s：%v", filepath.Base(p), err))
			continue
		}
		if t.AppDigest != digest {
			d.Notes = append(d.Notes, fmt.Sprintf("略過 %s：側錄時的應用內容與目前不同，請重新側錄", filepath.Base(p)))
			continue
		}
		rel, _ := filepath.Rel(appRoot, p)
		rel = filepath.ToSlash(rel)
		trig := evidence.CommandString(t.Command)
		if t.ExitCode != 0 && !interrupted(t.ExitCode) {
			if !opt.IncludeFailed {
				failed = append(failed, fmt.Sprintf("%s（結束碼 %d：%s）", filepath.Base(p), t.ExitCode, trig))
				continue
			}
			d.Notes = append(d.Notes, fmt.Sprintf("⚠ 已依 --include-failed 採用失敗的側錄 %s（結束碼 %d：%s）當證據；它引用的行為可能來自錯誤處理路徑", filepath.Base(p), t.ExitCode, trig))
		} else if interrupted(t.ExitCode) {
			d.Notes = append(d.Notes, fmt.Sprintf("%s 的指令以結束碼 %d 結束（被 Ctrl+C 或 SIGTERM 中斷），視為正常停止並採用：%s", filepath.Base(p), t.ExitCode, trig))
		}
		lastCmd = t.Command
		lastTrace = filepath.Base(p)
		for _, e := range t.Events {
			switch e.Channel {
			case evidence.ChanFile:
				s := files[e.Root]
				if s == nil {
					s = &seen{trace: rel, trigger: trig}
					files[e.Root] = s
				}
				if e.Op == "write" && !s.write {
					s.write = true
					s.trace, s.trigger = rel, trig
				}
			case evidence.ChanEgress:
				k := fmt.Sprintf("%s:%d", e.Host, e.Port)
				if e.Decision == "blocked" {
					blocked[k] = e.Reason
					continue
				}
				if egress[k] == nil {
					egress[k] = &seen{trace: rel, trigger: trig}
				}
			case evidence.ChanIngress:
				if ingress[e.Port] == nil {
					ingress[e.Port] = &seen{trace: rel, trigger: trig}
				}
				if !contains(listenCmds[e.Port], trig) {
					listenCmds[e.Port] = append(listenCmds[e.Port], trig)
				}
			case evidence.ChanSecret:
				if e.Location != "header" {
					visibleOnly[e.Name] = fmt.Sprintf("%s（%s）", e.Host, e.Location)
					continue
				}
				k := secretKey{e.Name, e.Host, e.Header}
				if secrets[k] == nil {
					secrets[k] = &seen{trace: rel, trigger: trig}
				}
			}
		}
	}
	if len(failed) > 0 {
		d.Notes = append(d.Notes, "已略過結束碼非 0 的側錄（不當證據）："+strings.Join(failed, "；")+"。若確實要用，請加 --include-failed；不需要的側錄檔可移出 .warp/evidence/")
	}
	if lastCmd == nil {
		return nil, fmt.Errorf("沒有任何可用的側錄紀錄：%s", strings.Join(d.Notes, "；"))
	}
	name := strings.ToLower(filepath.Base(appRoot))
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	version, vsrc := appVersion(appRoot)
	if vsrc == "" {
		d.Notes = append(d.Notes, "找不到 package.json 或 pyproject.toml 中的版本，app.version 暫填 "+version+"；請改成應用的實際版本")
	} else {
		d.Notes = append(d.Notes, fmt.Sprintf("app.version 取自 %s：%s", vsrc, version))
	}
	m := &manifest.Manifest{
		Warp: manifest.FormatVersion,
		App: manifest.App{
			Name: strings.Trim(name, "-_"), DisplayName: filepath.Base(appRoot), Version: version,
			Kind: "cli", Entry: lastCmd, Digest: digest,
		},
		Runtime: manifest.Runtime{
			Isolation: "process",
			Resources: manifest.Resources{CPU: 1, Memory: "512Mi", Pids: 128, Disk: "1Gi"},
			Spawn:     "none",
		},
		Exceptions: []manifest.Exception{},
		Evidence:   []manifest.Evidence{},
	}
	entryNote := fmt.Sprintf("⚠ 請確認 app.entry：初稿取自最後一次採用的側錄（%s）的指令 %s，連同其中所有參數；若那是測試指令或帶有一次性的參數，請改成正式的啟動指令", lastTrace, evidence.CommandString(lastCmd))
	d.Notes = append(d.Notes, entryNote)
	d.Notes = append(d.Notes, "app.kind 暫填 cli；請依應用型態改成 cli | desktop | local-web | hosted | mcp-server | agent | job")
	for _, p := range sortedInts(listenCmds) {
		d.Notes = append(d.Notes, fmt.Sprintf("network.ingress（%d 埠）來自側錄中的監聽：%s。若這是測試時臨時開的伺服器而不是應用提供的介面，請刪除這條授權與對應的 evidence", p, strings.Join(listenCmds[p], "；")))
	}
	addEv := func(grant string, s *seen) {
		m.Evidence = append(m.Evidence, manifest.Evidence{Grant: grant, ObservedIn: s.trace, TriggeredBy: s.trigger})
	}
	// Files: APP_DATA, APP_CACHE, then picks.
	var roots []string
	for r := range files {
		roots = append(roots, r)
	}
	order := func(r string) string {
		switch r {
		case manifest.VarAppData:
			return "0"
		case manifest.VarAppCache:
			return "1"
		}
		return "2" + r
	}
	sort.Slice(roots, func(i, j int) bool { return order(roots[i]) < order(roots[j]) })
	for _, r := range roots {
		if _, _, ok := manifest.PathVar(r); !ok {
			continue
		}
		s := files[r]
		mode := "ro"
		if s.write {
			mode = "rw"
		}
		m.Files = append(m.Files, manifest.FileGrant{Path: r, Mode: mode, Purpose: PurposePlaceholder})
		addEv(manifest.GrantRef(manifest.GrantFile, len(m.Files)-1), s)
	}
	for _, k := range sortedKeys(egress) {
		host, port := splitHostPort(k)
		m.Network.Egress = append(m.Network.Egress, manifest.Egress{Host: host, Port: port, Purpose: PurposePlaceholder})
		addEv(manifest.GrantRef(manifest.GrantEgress, len(m.Network.Egress)-1), egress[k])
	}
	var ports []int
	for p := range ingress {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		m.Network.Ingress = append(m.Network.Ingress, manifest.Ingress{Listen: p, Expose: "loopback", Auth: "local-token", Purpose: PurposePlaceholder})
		addEv(manifest.GrantRef(manifest.GrantIngress, len(m.Network.Ingress)-1), ingress[p])
	}
	var sks []secretKey
	for k := range secrets {
		sks = append(sks, k)
	}
	sort.Slice(sks, func(i, j int) bool { return sks[i].name+sks[i].host < sks[j].name+sks[j].host })
	used := map[string]bool{}
	for _, k := range sks {
		if used[k.name] {
			d.Notes = append(d.Notes, fmt.Sprintf("機密 %s 也被送往 %s；初稿只綁定一個主機，其他目的地不會取得真值", k.name, k.host))
			continue
		}
		used[k.name] = true
		m.Secrets = append(m.Secrets, manifest.Secret{
			Name: k.name, ProvidedBy: "recipient", Visibility: "gate-only", Purpose: PurposePlaceholder,
			Bind: manifest.SecretBind{Host: k.host, Inject: manifest.SecretInject{Header: k.header}},
		})
		addEv(manifest.GrantRef(manifest.GrantSecret, len(m.Secrets)-1), secrets[k])
	}
	for n, where := range visibleOnly {
		if !used[n] {
			d.Notes = append(d.Notes, fmt.Sprintf("⚠ 機密 %s 只出現在 %s，不在請求標頭中。核心目前只能把機密注入請求標頭，這個機密在此版核心中無法授權（改成 app-visible 也不行：檢查器要求 bind.inject.header，證據也必須是標頭）；初稿未授權。需要修改應用改用標頭傳送金鑰，或等核心支援——請交給人決定", n, where))
		}
	}
	for _, k := range sortedKeysStr(blocked) {
		m.DeniedByDesign = append(m.DeniedByDesign, manifest.Denied{
			Behavior: "對外連線 " + k,
			Reason:   "側錄時即被核心阻擋（" + blocked[k] + "）；若確實需要，須人工核可例外",
		})
	}
	y, err := manifest.Marshal(m)
	if err != nil {
		return nil, err
	}
	header := "# 由 warp draft 依側錄紀錄產生的宣告初稿。\n# 請逐條收緊、填寫每條授權的 purpose（一句人話），再執行 warp lint。\n" +
		"# ⚠ app.entry 取自最後一次側錄的指令（含參數），app.kind 暫填 cli：請確認或改正。\n"
	d.Manifest = m
	d.YAML = append([]byte(header), y...)
	return d, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedInts(m map[int][]string) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// appVersion reads the app's own version from package.json or
// pyproject.toml at the app root ("0.1.0" and no source if none).
func appVersion(root string) (version, source string) {
	if b, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		var pj struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &pj) == nil && validVersion(pj.Version) {
			return pj.Version, "package.json"
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "pyproject.toml")); err == nil {
		section := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = strings.Trim(line, "[] ")
				continue
			}
			if section != "project" && section != "tool.poetry" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != "version" {
				continue
			}
			v = strings.TrimSpace(v)
			if i := strings.Index(v, "#"); i > 0 && (strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'")) {
				v = strings.TrimSpace(v[:i])
			}
			v = strings.Trim(v, `"'`)
			if validVersion(v) {
				return v, "pyproject.toml"
			}
		}
	}
	return "0.1.0", ""
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r == '.' || r == '-' || r == '+' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]*seen) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysStr(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func splitHostPort(k string) (string, int) {
	i := strings.LastIndexByte(k, ':')
	var p int
	fmt.Sscanf(k[i+1:], "%d", &p)
	return k[:i], p
}
