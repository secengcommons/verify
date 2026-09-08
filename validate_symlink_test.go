//go:build !windows

package verify

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdmissionCanonicalisesExecutableSymlink(t *testing.T) {
	root := t.TempDir()
	targetDirectory := t.TempDir()
	target := filepath.Join(targetDirectory, "tool")
	if err := os.WriteFile(target, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "tool")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	plan := Plan{ID: "plan", Profiles: []Profile{{ID: "profile", Controls: []Control{{
		ID: "control", Name: "Control", Command: Command{Executable: link, Timeout: time.Second, OutputLimit: 1},
	}}}}}
	target, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := admit(root, plan)
	if err != nil || admitted.profiles[0].Controls[0].Command.Executable != target {
		t.Fatalf("admitted executable = (%q, %v)", admitted.profiles[0].Controls[0].Command.Executable, err)
	}
	if err = os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, err = admit(root, plan); err == nil {
		t.Fatal("dangling executable symlink was accepted")
	}
}
