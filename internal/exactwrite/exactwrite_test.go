package exactwrite

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBytes(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := Bytes(&output, []byte("value")); err != nil || output.String() != "value" {
		t.Fatalf("Bytes = (%q, %v)", output.String(), err)
	}
	var partial partialWriter
	if err := Bytes(&partial, []byte("value")); err != nil || partial.String() != "value" {
		t.Fatalf("partial Bytes = (%q, %v)", partial.String(), err)
	}
	failure := errors.New("write")
	for _, test := range []struct {
		writer io.Writer
		want   error
	}{
		{writer: fixedWriter{count: 0}, want: io.ErrNoProgress},
		{writer: fixedWriter{count: -1}},
		{writer: fixedWriter{count: 6}},
		{writer: fixedWriter{err: failure}, want: failure},
	} {
		if err := Bytes(test.writer, []byte("value")); err == nil || test.want != nil && !errors.Is(err, test.want) {
			t.Fatalf("Bytes with %#v = %v", test, err)
		}
	}
}

type fixedWriter struct {
	count int
	err   error
}

func (writer fixedWriter) Write([]byte) (int, error) { return writer.count, writer.err }

type partialWriter struct{ bytes.Buffer }

func (writer *partialWriter) Write(value []byte) (int, error) {
	return writer.Buffer.Write(value[:min(2, len(value))])
}
