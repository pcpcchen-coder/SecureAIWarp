// Package state locates the core's private state outside every shell: the
// ledger, persistent APP_DATA, usage counters and the trace signing key.
// None of these paths is ever mounted into a shell.
package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Root returns the core state root.
func Root() (string, error) {
	if d := os.Getenv("WARP_STATE_DIR"); d != "" {
		return filepath.Abs(d)
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "securewarp"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("無法決定狀態目錄：請設定 WARP_STATE_DIR")
	}
	return filepath.Join(home, ".local", "state", "securewarp"), nil
}

var unsafeName = regexp.MustCompile(`[^a-z0-9_-]+`)

// AppDir returns (and creates) the per-app state directory. It is keyed by
// the app name and the absolute app root so two copies never share state.
func AppDir(appRoot, name string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(appRoot))
	n := unsafeName.ReplaceAllString(strings.ToLower(name), "-")
	if n == "" {
		n = "app"
	}
	if len(n) > 40 {
		n = n[:40]
	}
	dir := filepath.Join(root, "apps", n+"-"+hex.EncodeToString(sum[:6]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("無法建立狀態目錄：%w", err)
	}
	return dir, nil
}

// checkPrivate refuses a key file that someone other than its owner could
// read or replace. The key only keeps other OS users (and the app inside
// the shell, which never sees the state directory) from forging traces;
// it cannot keep out a process running as the same user.
func checkPrivate(p string, st os.FileInfo) error {
	if !st.Mode().IsRegular() {
		return fmt.Errorf("側錄簽章金鑰 %s 不是一般檔案（可能是符號連結），拒絕使用", p)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("側錄簽章金鑰 %s 的權限為 %v，其他使用者可讀寫；拒絕使用（請改為 0600 或刪除後重新產生，舊的側錄檔需重新側錄）", p, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("側錄簽章金鑰 %s 不屬於目前的使用者（uid %d），拒絕使用", p, sys.Uid)
	}
	return nil
}

// TraceKey returns the per-user key used to sign traces, creating it once.
func TraceKey() ([]byte, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(root, "trace.key")
	if st, err := os.Lstat(p); err == nil {
		if err := checkPrivate(p, st); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("側錄簽章金鑰 %s 已損毀", p)
		}
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return TraceKey()
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, nil
}
