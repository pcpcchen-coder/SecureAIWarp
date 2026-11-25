package gate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrUploadLimit is returned when a destination's daily upload cap is hit.
var ErrUploadLimit = errors.New("upload limit exceeded")

// Usage tracks uploaded bytes per destination per UTC day, persisted in the
// core's state directory so the cap holds across runs of the same app.
type Usage struct {
	mu    sync.Mutex
	dir   string
	day   string
	bytes map[string]int64
	saved time.Time
}

// flushEvery bounds how much accounted upload can be lost (and so sent
// again for free on the next run) if the core dies without cleaning up.
const flushEvery = time.Second

func usagePath(dir, day string) string { return filepath.Join(dir, "usage-"+day+".json") }

// OpenUsage loads today's counters.
func OpenUsage(dir string) *Usage {
	u := &Usage{dir: dir, bytes: map[string]int64{}}
	u.day = time.Now().UTC().Format("20060102")
	if b, err := os.ReadFile(usagePath(dir, u.day)); err == nil {
		_ = json.Unmarshal(b, &u.bytes)
	}
	return u
}

// Add accounts n bytes for target and fails once limit is exceeded.
func (u *Usage) Add(target string, n, limit int64) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.bytes[target]+n > limit {
		u.bytes[target] = limit
		u.flushLocked()
		return ErrUploadLimit
	}
	u.bytes[target] += n
	if time.Since(u.saved) >= flushEvery {
		u.flushLocked()
	}
	return nil
}

func (u *Usage) flushLocked() {
	if u.dir == "" {
		return
	}
	u.saved = time.Now()
	b, _ := json.Marshal(u.bytes)
	tmp := usagePath(u.dir, u.day) + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, usagePath(u.dir, u.day))
	}
}

// Flush persists the counters.
func (u *Usage) Flush() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.flushLocked()
}
