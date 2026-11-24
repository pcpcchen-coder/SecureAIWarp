// Package draft derives a first-cut manifest from record-mode traces. Every
// observed behaviour becomes the narrowest grant with an evidence pointer;
// purposes are left as placeholders that lint rejects until a person or
// agent writes them.
package draft

import (
	"fmt"
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

// FromDir builds a draft from every valid trace in dir.
func FromDir(appRoot, dir string, key []byte) (*Draft, error) {
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
	var lastCmd []string
	for _, p := range paths {
		t, err := evidence.Load(p, key)
		if err != nil {
			d.Notes = append(d.Notes, fmt.Sprintf("略過 %s：%v", filepath.Base(p), err))
			continue
		}
		rel, _ := filepath.Rel(appRoot, p)
		rel = filepath.ToSlash(rel)
		trig := strings.Join(t.Command, " ")
		lastCmd = t.Command
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
	if lastCmd == nil {
		return nil, fmt.Errorf("沒有任何有效的側錄紀錄")
	}
	digest, err := manifest.ComputeDigest(appRoot)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(filepath.Base(appRoot))
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	m := &manifest.Manifest{
		Warp: manifest.FormatVersion,
		App: manifest.App{
			Name: strings.Trim(name, "-_"), DisplayName: filepath.Base(appRoot), Version: "0.1.0",
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
	if len(ingress) > 0 {
		m.App.Kind = "local-web"
	}
	d.Notes = append(d.Notes, fmt.Sprintf("app.entry 取自最後一次側錄的指令 %q；若那是測試指令，請改成正式的啟動指令", strings.Join(lastCmd, " ")))
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
			d.Notes = append(d.Notes, fmt.Sprintf("機密 %s 只出現在 %s 而非標頭，無法由閘門注入；初稿未授權，若確實需要只能改為 app-visible 例外", n, where))
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
	header := "# 由 warp draft 依側錄紀錄產生的宣告初稿。\n# 請逐條收緊、填寫每條授權的 purpose（一句人話），再執行 warp lint。\n"
	d.Manifest = m
	d.YAML = append([]byte(header), y...)
	return d, nil
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
