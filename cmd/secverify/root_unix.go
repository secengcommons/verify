//go:build !windows

package main

import "path/filepath"

func canonicalRepositoryRoot(root string) (string, error) {
	return filepath.EvalSymlinks(root)
}
