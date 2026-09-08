package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCanonicalRepositoryRootWindowsFailures(t *testing.T) {
	failure := errors.New("failure")
	if _, err := canonicalRepositoryRootWith("root", func(string) (string, error) {
		return "", failure
	}, os.Open, readFinalWindowsPath); !errors.Is(err, failure) {
		t.Fatalf("evaluation error = %v", err)
	}
	if _, err := canonicalRepositoryRootWith("root", func(string) (string, error) {
		return "missing", nil
	}, func(string) (*os.File, error) {
		return nil, failure
	}, readFinalWindowsPath); !errors.Is(err, failure) {
		t.Fatalf("open error = %v", err)
	}
	opened, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = canonicalRepositoryRootWith("root", func(string) (string, error) {
		return "root", nil
	}, func(string) (*os.File, error) {
		return opened, nil
	}, func(windows.Handle) (string, error) {
		return "", failure
	}); !errors.Is(err, failure) {
		t.Fatalf("final-path error = %v", err)
	}
}

func TestReadFinalWindowsPath(t *testing.T) {
	const expected = "C"
	calls := 0
	result, err := readFinalWindowsPathWith(0, func(_ windows.Handle, buffer *uint16, size, _ uint32) (uint32, error) {
		calls++
		if calls == 1 {
			return initialFinalPathCharacters + 1, nil
		}
		*buffer = uint16(expected[0])
		return 1, nil
	})
	if err != nil || result != expected || calls != 2 {
		t.Fatalf("final path = (%q, %d, %v)", result, calls, err)
	}
	failure := errors.New("failure")
	if _, err = readFinalWindowsPathWith(0, func(windows.Handle, *uint16, uint32, uint32) (uint32, error) {
		return 0, failure
	}); !errors.Is(err, failure) {
		t.Fatalf("API error = %v", err)
	}
	if _, err = readFinalWindowsPathWith(0, func(windows.Handle, *uint16, uint32, uint32) (uint32, error) {
		return maximumFinalPathCharacters, nil
	}); !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
		t.Fatalf("overflow error = %v", err)
	}
}

func TestCleanFinalWindowsPath(t *testing.T) {
	for source, expected := range map[string]string{
		`\\?\C:\repository`:    `C:\repository`,
		`\\?\UNC\server\share`: `\\server\share`,
	} {
		if result := cleanFinalWindowsPath(source); result != filepath.Clean(expected) {
			t.Fatalf("cleanFinalWindowsPath(%q) = %q", source, result)
		}
	}
}
