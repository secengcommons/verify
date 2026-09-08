package verify

import (
	"os"
	"path/filepath"
)

func canonicalExecutablePlatform(path string) (string, error) {
	return canonicalWindowsExecutableWith(path, os.Lstat, filepath.EvalSymlinks, os.Stat)
}

func canonicalWindowsExecutableWith(
	path string,
	lstat func(string) (os.FileInfo, error),
	evaluate func(string) (string, error),
	stat func(string) (os.FileInfo, error),
) (string, error) {
	information, err := lstat(path)
	if err != nil {
		return "", err
	}
	resolve := func(value string) (string, error) {
		if information.Mode()&os.ModeSymlink != 0 {
			return evaluate(value)
		}
		return filepath.Clean(value), nil
	}
	return canonicalExecutableWith(path, resolve, stat)
}
