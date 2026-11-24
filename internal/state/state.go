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
	if b, err := os.ReadFile(p); err == nil {
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
