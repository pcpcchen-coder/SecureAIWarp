package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// systemDirs may never be mounted from the host as app roots or picks.
var systemDirs = []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/run", "/sbin", "/sys", "/usr", "/var", "/root", "/home", "/opt", "/srv", "/mnt", "/media",
	"/tmp", "/var/tmp", "/snap", "/Applications", "/Library", "/System", "/Users", "/private"}

// credentialEntries are paths (relative to a home-like directory) that hold
// credentials. A mount that is, contains or lies inside one is refused.
var credentialEntries = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure",
	".config/gcloud", ".config/gh", ".netrc", ".password-store", ".mozilla",
	".config/google-chrome", ".config/chromium", ".local/share/keyrings", ".pki",
	".git-credentials", ".npmrc", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
	"Library/Keychains", "Library/Application Support/Google/Chrome"}

// controlSockets are container runtime control interfaces.
var controlSockets = []string{"docker.sock", "containerd.sock", "podman.sock", "crio.sock", "dockershim.sock"}

func within(path, dir string) bool {
	if dir == "/" {
		return true
	}
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}

func realAbs(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(a)
}

// checkHostMount applies the hard rules for any host directory that is
// mounted into a shell (the app root and every USER_PICK).
func checkHostMount(what, p string, protect []string) error {
	st, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("%s %s：%w", what, p, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s %s 必須是資料夾", what, p)
	}
	for _, d := range systemDirs {
		if p == d {
			return fmt.Errorf("%s 不可以是系統目錄或根目錄：%s", what, p)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if rh, err := filepath.EvalSymlinks(home); err == nil {
			home = rh
		}
		if within(home, p) {
			return fmt.Errorf("%s 不可以是家目錄或其上層目錄：%s", what, p)
		}
		for _, c := range credentialEntries {
			if within(p, filepath.Join(home, c)) {
				return fmt.Errorf("%s 位於憑證目錄內，拒絕掛載：%s", what, p)
			}
		}
	}
	for _, c := range credentialEntries {
		if _, err := os.Lstat(filepath.Join(p, c)); err == nil {
			return fmt.Errorf("%s 內含憑證目錄 %s，看起來像家目錄，拒絕掛載：%s", what, c, p)
		}
		base := filepath.Base(c)
		if filepath.Base(p) == base && strings.HasPrefix(base, ".") {
			return fmt.Errorf("%s 看起來是憑證目錄，拒絕掛載：%s", what, p)
		}
	}
	// Refuse container control sockets anywhere directly inside.
	if ents, err := os.ReadDir(p); err == nil {
		for _, e := range ents {
			for _, s := range controlSockets {
				if e.Name() == s {
					return fmt.Errorf("%s 內含容器執行環境的控制介面 %s，拒絕掛載", what, s)
				}
			}
		}
	}
	for _, pr := range protect {
		if pr == "" {
			continue
		}
		if within(p, pr) || within(pr, p) {
			return fmt.Errorf("%s %s 與核心的狀態目錄或應用目錄重疊，拒絕掛載", what, p)
		}
	}
	return nil
}
