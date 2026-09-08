package verify

import (
	"errors"
	"os"
	"testing"
)

func TestCanonicalWindowsExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := canonicalExecutablePlatform(executable); err != nil || result != executable {
		t.Fatalf("ordinary executable = (%q, %v)", result, err)
	}
	failure := errors.New("failure")
	if _, err := canonicalWindowsExecutableWith(executable, func(string) (os.FileInfo, error) {
		return nil, failure
	}, nil, nil); !errors.Is(err, failure) {
		t.Fatalf("lstat error = %v", err)
	}
	information, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	symlink := fileInfoWithMode{FileInfo: information, mode: information.Mode() | os.ModeSymlink}
	if _, err = canonicalWindowsExecutableWith(executable, func(string) (os.FileInfo, error) {
		return symlink, nil
	}, func(string) (string, error) {
		return "", failure
	}, os.Stat); !errors.Is(err, failure) {
		t.Fatalf("symlink error = %v", err)
	}
}

type fileInfoWithMode struct {
	os.FileInfo
	mode os.FileMode
}

func (value fileInfoWithMode) Mode() os.FileMode {
	return value.mode
}
