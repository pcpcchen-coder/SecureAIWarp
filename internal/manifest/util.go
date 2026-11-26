package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Grant kinds addressable by evidence and exceptions.
const (
	GrantFile    = "files"
	GrantEgress  = "network.egress"
	GrantIngress = "network.ingress"
	GrantSecret  = "secrets"
)

var grantRe = regexp.MustCompile(`^(files|network\.egress|network\.ingress|secrets)\[(\d+)\]$`)

// ParseGrant splits "network.egress[1]" into its kind and index.
func ParseGrant(s string) (kind string, idx int, ok bool) {
	m := grantRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil || n > 1<<20 {
		return "", 0, false
	}
	return m[1], n, true
}

// GrantRef formats a grant reference.
func GrantRef(kind string, idx int) string { return fmt.Sprintf("%s[%d]", kind, idx) }

// AllGrants lists every grant reference in the manifest.
func (m *Manifest) AllGrants() []string {
	var out []string
	for i := range m.Files {
		out = append(out, GrantRef(GrantFile, i))
	}
	for i := range m.Network.Egress {
		out = append(out, GrantRef(GrantEgress, i))
	}
	for i := range m.Network.Ingress {
		out = append(out, GrantRef(GrantIngress, i))
	}
	for i := range m.Secrets {
		out = append(out, GrantRef(GrantSecret, i))
	}
	return out
}

// GrantExists reports whether the reference points at an existing grant.
func (m *Manifest) GrantExists(ref string) bool {
	kind, idx, ok := ParseGrant(ref)
	if !ok {
		return false
	}
	switch kind {
	case GrantFile:
		return idx < len(m.Files)
	case GrantEgress:
		return idx < len(m.Network.Egress)
	case GrantIngress:
		return idx < len(m.Network.Ingress)
	case GrantSecret:
		return idx < len(m.Secrets)
	}
	return false
}

// Path variables.
const (
	VarAppData  = "${APP_DATA}"
	VarAppCache = "${APP_CACHE}"
)

var pickRe = regexp.MustCompile(`^\$\{USER_PICK:([a-z][a-z0-9_-]{0,31})\}$`) // keep in sync with pickNameRe

// PathVar classifies a files[].path value. It returns the pick name for
// USER_PICK paths. Only variable paths are supported in phase 1.
func PathVar(p string) (kind string, pick string, ok bool) {
	switch p {
	case VarAppData:
		return "APP_DATA", "", true
	case VarAppCache:
		return "APP_CACHE", "", true
	}
	if m := pickRe.FindStringSubmatch(p); m != nil {
		return "USER_PICK", m[1], true
	}
	return "", "", false
}

// PickVar formats a USER_PICK variable.
func PickVar(name string) string { return "${USER_PICK:" + name + "}" }

// ParseSize parses sizes like "512Mi", "1Gi", "100Ki", "10M", "4096".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("空的大小")
	}
	units := []struct {
		suf string
		mul int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}}
	mul := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suf) {
			mul = u.mul
			s = strings.TrimSuffix(s, u.suf)
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("無效的大小 %q", s)
	}
	if n > (1<<62)/mul {
		return 0, fmt.Errorf("大小過大")
	}
	return n * mul, nil
}

// HiddenAppEntries are top-level entries of the app root that are excluded
// from the content digest and hidden (masked) inside the shell.
var HiddenAppEntries = []string{".warp", ".git"}

// ComputeDigest hashes the app root deterministically: every regular file,
// directory and symlink (except the hidden top-level entries) contributes
// its relative path, type, permission bits and content (or link target).
func ComputeDigest(root string) (string, error) {
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		top := strings.SplitN(rel, "/", 2)[0]
		for _, h := range HiddenAppEntries {
			if top == h {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			lines = append(lines, fmt.Sprintf("d %o %s", mode.Perm(), rel))
		case mode&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			lines = append(lines, fmt.Sprintf("l %s -> %s", rel, t))
		case mode.IsRegular():
			h, err := hashFile(p)
			if err != nil {
				return err
			}
			lines = append(lines, fmt.Sprintf("f %o %s %s", mode.Perm(), rel, h))
		default:
			return fmt.Errorf("應用目錄中有不支援的檔案類型：%s", rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		io.WriteString(h, l)
		io.WriteString(h, "\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var pickNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// PickNameRule describes valid USER_PICK names for error messages.
const PickNameRule = "名稱必須以小寫英文字母開頭，只含小寫英數字、- 與 _，最多 32 字元（例如 notes、photo-in）"

// ValidPickName reports whether name is a valid USER_PICK name.
func ValidPickName(name string) bool { return pickNameRe.MatchString(name) }

// PickEnvName is the environment variable that tells the app where a
// picked folder is mounted inside the shell (WARP_PICK_<NAME>, upper case,
// "-" replaced by "_").
func PickEnvName(name string) string {
	return "WARP_PICK_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// argVarRe finds the fixed placeholders that may appear in a command line.
// Anything else (including other ${...} text) is passed through untouched.
var argVarRe = regexp.MustCompile(`\$\{(APP_DATA|APP_CACHE|USER_PICK:[^}]*)\}`)

// ArgVars lists the placeholders used in argv, as they would appear in
// files[].path (e.g. "${USER_PICK:notes}"), in order of first use. Invalid
// USER_PICK names are returned too so callers can report them.
func ArgVars(argv []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range argv {
		for _, m := range argVarRe.FindAllString(a, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// ExpandArgs replaces ${APP_DATA}, ${APP_CACHE} and ${USER_PICK:<name>} in
// every argument by their shell paths (a literal substring replacement; no
// other expansion of any kind). paths maps a placeholder to its shell path;
// a placeholder that is not in paths is an error, so a command can never
// run with a placeholder it was not given.
func ExpandArgs(argv []string, paths map[string]string) ([]string, error) {
	out := make([]string, len(argv))
	for i, a := range argv {
		var missing string
		out[i] = argVarRe.ReplaceAllStringFunc(a, func(m string) string {
			if p, ok := paths[m]; ok {
				return p
			}
			if missing == "" {
				missing = m
			}
			return m
		})
		if missing != "" {
			if strings.HasPrefix(missing, "${USER_PICK:") {
				if _, _, ok := PathVar(missing); !ok {
					return nil, fmt.Errorf("指令中的 %s 不是有效的選定資料夾佔位字：%s", missing, PickNameRule)
				}
				return nil, fmt.Errorf("指令引用了 %s，但這次執行沒有掛載這個資料夾（record 請加 --pick 名稱=資料夾；enforce 只能使用宣告中的 USER_PICK）", missing)
			}
			return nil, fmt.Errorf("指令引用了 %s，但這次執行沒有掛載它（enforce 只掛載宣告在 files 中的路徑）", missing)
		}
	}
	return out, nil
}
