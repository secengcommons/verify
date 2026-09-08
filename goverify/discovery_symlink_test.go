//go:build !windows

package goverify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRepositoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
	if err := os.Symlink("go.mod", filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverRepository(t.Context(), root, discoveryGoTool(t)); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yml")
	if err := os.WriteFile(target, []byte("jobs: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := ".github/workflows/value.yml"
	link := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "owned")
	writeDiscoveryFile(t, target, "workflows/value.yml", "jobs: {}\n")
	if err := os.Symlink(target, filepath.Join(root, ".github")); err != nil {
		t.Fatal(err)
	}
	path := ".github/workflows/value.yml"
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("intermediate symlink error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsLocalActionMetadataSymlink(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/value.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	target := filepath.Join(root, "metadata.yml")
	writeDiscoveryFile(t, root, "metadata.yml", "name: check\nruns: {using: composite, steps: []}\n")
	directory := filepath.Join(root, ".github", "actions", "check")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "action.yml")); err != nil {
		t.Fatal(err)
	}
	writeDiscoveryFile(t, root, ".github/actions/check/action.yaml", "name: alternate\nruns: {using: composite, steps: []}\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("metadata symlink error = %v", err)
	}
}
