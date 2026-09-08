package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const createJunctionCommand = `New-Item -ItemType Junction -Path $env:SECVERIFY_TEST_LINK -Target $env:SECVERIFY_TEST_TARGET -ErrorAction Stop | Out-Null`

func createRepositoryLink(t *testing.T, target, link string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", createJunctionCommand)
	command.Env = append(os.Environ(), "SECVERIFY_TEST_LINK="+link, "SECVERIFY_TEST_TARGET="+target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("create repository junction: %v: %s", err, output)
	}
}

func TestCreateRepositoryLinkTreatsPathsAsData(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target & source")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(root, "link & selected")
	createRepositoryLink(t, target, link)
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("inspect target: %v", err)
	}
	linkInfo, err := os.Stat(link)
	if err != nil {
		t.Fatalf("inspect link: %v", err)
	}
	if !os.SameFile(targetInfo, linkInfo) {
		t.Fatal("junction does not identify the target")
	}
}
