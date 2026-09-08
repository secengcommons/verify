package goverify

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
)

type boundedSource struct {
	reader io.Reader
	stat   func() (os.FileInfo, error)
	close  func() error
}

const maxSourceBytes = 1 << 20

func readBoundedSource(source boundedSource, class error) ([]byte, error) {
	return readBoundedSourceLimit(source, class, maxSourceBytes)
}

func readBoundedSourceLimit(source boundedSource, class error, maximum int64) ([]byte, error) {
	information, statErr := source.stat()
	if statErr != nil || information == nil || !information.Mode().IsRegular() || information.Size() < 0 || information.Size() > maximum {
		return nil, errors.Join(class, statErr, source.close())
	}
	size := information.Size()
	value := make([]byte, size+1)
	read, readErr := io.ReadFull(source.reader, value)
	closeErr := source.close()
	complete := int64(read) == size && (errors.Is(readErr, io.ErrUnexpectedEOF) || size == 0 && errors.Is(readErr, io.EOF))
	if !complete || closeErr != nil {
		return nil, errors.Join(class, readErr, closeErr)
	}
	return value[:read], nil
}

func readBoundedDirectory(
	ctx context.Context,
	readDirectory func(int) ([]os.DirEntry, error),
	closeDirectory func() error,
	remaining int,
	class error,
) ([]os.DirEntry, error) {
	if remaining < 0 {
		return nil, errors.Join(class, closeDirectory())
	}
	entries := make([]os.DirEntry, 0)
	var readErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(class, err, closeDirectory())
		}
		var batch []os.DirEntry
		batch, readErr = readDirectory(remaining - len(entries) + 1)
		entries = append(entries, batch...)
		if len(entries) > remaining || readErr != nil || len(batch) == 0 {
			break
		}
	}
	closeErr := closeDirectory()
	if len(entries) > remaining || readErr != nil && !errors.Is(readErr, io.EOF) || readErr == nil {
		return nil, errors.Join(class, readErr, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(class, closeErr)
	}
	slices.SortFunc(entries, func(left, right os.DirEntry) int { return strings.Compare(left.Name(), right.Name()) })
	return entries, nil
}
