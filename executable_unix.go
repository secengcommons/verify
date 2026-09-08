//go:build !windows

package verify

import (
	"os"
	"path/filepath"
)

func canonicalExecutablePlatform(path string) (string, error) {
	return canonicalExecutableWith(path, filepath.EvalSymlinks, os.Stat)
}
