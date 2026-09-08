//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func createRepositoryLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create repository symlink: %v", err)
	}
}

func TestRepositoryRootSelectionCanonicalisesLink(t *testing.T) {
	root := t.TempDir()
	parent := t.TempDir()
	linked := filepath.Join(parent, "repository")
	createRepositoryLink(t, root, linked)
	selected, err := resolveRepositoryRoot(parent, "repository")
	if err != nil {
		t.Fatalf("resolve repository link: %v", err)
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if selected != filepath.Clean(want) {
		t.Fatalf("selected root = %q, want %q", selected, want)
	}
}
