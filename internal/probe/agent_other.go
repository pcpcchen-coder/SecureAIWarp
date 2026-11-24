//go:build !linux

package probe

// RunHidden is only available on Linux.
func RunHidden(string, []string) int { return 2 }
