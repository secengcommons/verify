package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const initialFinalPathCharacters = 512
const maximumFinalPathCharacters = 1 << 15

func canonicalRepositoryRoot(root string) (result string, err error) {
	return canonicalRepositoryRootWith(root, filepath.EvalSymlinks, os.Open, readFinalWindowsPath)
}

func canonicalRepositoryRootWith(
	root string,
	evaluate func(string) (string, error),
	open func(string) (*os.File, error),
	final func(windows.Handle) (string, error),
) (result string, err error) {
	resolved, err := evaluate(root)
	if err != nil {
		return "", err
	}
	opened, err := open(resolved)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, opened.Close()) }()
	return final(windows.Handle(opened.Fd()))
}

func readFinalWindowsPath(handle windows.Handle) (string, error) {
	return readFinalWindowsPathWith(handle, windows.GetFinalPathNameByHandle)
}

func readFinalWindowsPathWith(
	handle windows.Handle,
	get func(windows.Handle, *uint16, uint32, uint32) (uint32, error),
) (string, error) {
	size := uint32(initialFinalPathCharacters)
	buffer := make([]uint16, size)
	for {
		length, pathErr := get(handle, &buffer[0], size, 0)
		if pathErr != nil {
			return "", pathErr
		}
		if length < size {
			return cleanFinalWindowsPath(windows.UTF16ToString(buffer[:length])), nil
		}
		if length >= maximumFinalPathCharacters {
			return "", windows.ERROR_BUFFER_OVERFLOW
		}
		size = length + 1
		buffer = make([]uint16, size)
	}
}

func cleanFinalWindowsPath(path string) string {
	if value, found := strings.CutPrefix(path, `\\?\UNC\`); found {
		return filepath.Clean(`\\` + value)
	}
	path = strings.TrimPrefix(path, `\\?\`)
	return filepath.Clean(path)
}
