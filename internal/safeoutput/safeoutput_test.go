package safeoutput

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"testing"
	"unicode"
	"unicode/utf8"
)

var writeResult error
var diagnosticResult string

const diagnosticFuzzBytes = 64 << 10

func TestWrite(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		source []byte
		want   string
	}{
		{name: "empty"},
		{name: "line", source: []byte("value\n"), want: "value\n"},
		{name: "final line", source: []byte("value"), want: "value\n"},
		{name: "Unicode", source: []byte("café\n"), want: "café\n"},
		{name: "GitHub command", source: []byte("::warning::value\n"), want: "\\x3a:warning::value\n"},
		{name: "leading GitHub command", source: []byte(" \t::warning::value\n"), want: " \t\\x3a:warning::value\n"},
		{name: "embedded Azure commands", source: []byte("prefix ##vso[task.logissue]value\nprefix ##[error]value\n"), want: "prefix \\x23#vso[task.logissue]value\nprefix \\x23#[error]value\n"},
		{name: "unsafe bytes", source: []byte{'\x1b', '[', '2', 'J', 0xff, '\r'}, want: "\\x1b[2J\\xff\\x0d\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Write(&output, test.source); err != nil || output.String() != test.want {
				t.Fatalf("Write = (%q, %v)", output.String(), err)
			}
		})
	}
}

func TestDiagnostic(t *testing.T) {
	t.Parallel()
	source := string(append([]byte("value\tline\n::warning::value ##vso[task.logissue]value ##[error]value\n\"quote\"\\"), '\x1b', 0xff))
	want := "value\\x09line\\x0a\\x3a:warning::value \\x23#vso[task.logissue]value \\x23#[error]value\\x0a\"quote\"\\\\x1b\\xff"
	if result := Diagnostic(source); result != want {
		t.Fatalf("Diagnostic = %q", result)
	}
}

func FuzzDiagnostic(f *testing.F) {
	for _, seed := range []string{"failure", "line\n::warning::value", "prefix ##vso[task.logissue]value", "prefix ##[error]value", "café", string([]byte{0xff})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > diagnosticFuzzBytes {
			return
		}
		first := Diagnostic(source)
		if second := Diagnostic(source); first != second {
			t.Fatal("diagnostic rendering is nondeterministic")
		}
		if !utf8.ValidString(first) {
			t.Fatalf("invalid diagnostic = %q", first)
		}
		for _, character := range first {
			if !strconv.IsPrint(character) {
				t.Fatalf("unsafe diagnostic character = %U", character)
			}
		}
	})
}

func FuzzWrite(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("ordinary output\n"),
		[]byte("::warning::value\n"),
		[]byte("prefix ##vso[task.logissue type=error]value\n"),
		[]byte("prefix ##[error]value\n"),
		{'\x1b', '[', '2', 'J', 0xff, '\r', '\n'},
		[]byte("café\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > diagnosticFuzzBytes {
			return
		}
		var first, second bytes.Buffer
		if err := Write(&first, source); err != nil {
			t.Fatal(err)
		}
		if err := Write(&second, source); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatal("rendered output is nondeterministic")
		}
		checkRenderedOutput(t, source, first.Bytes())
	})
}

func checkRenderedOutput(t *testing.T, source, rendered []byte) {
	t.Helper()
	if len(source) == 0 {
		if len(rendered) != 0 {
			t.Fatalf("empty output = %q", rendered)
		}
		return
	}
	if !utf8.Valid(rendered) || rendered[len(rendered)-1] != '\n' {
		t.Fatalf("invalid rendered output = %q", rendered)
	}
	for _, character := range string(rendered) {
		if character != '\n' && character != '\t' && !strconv.IsPrint(character) {
			t.Fatalf("unsafe rendered output = %q", rendered)
		}
	}
	for line := range bytes.SplitSeq(rendered, []byte{'\n'}) {
		if activeRunnerCommand(line) {
			t.Fatalf("workflow command remained active = %q", rendered)
		}
	}
}

func activeRunnerCommand(line []byte) bool {
	trimmed := bytes.TrimLeftFunc(line, unicode.IsSpace)
	return bytes.HasPrefix(trimmed, []byte("::")) || bytes.Contains(line, []byte("##vso[")) || bytes.Contains(line, []byte("##["))
}

func TestWriterFailures(t *testing.T) {
	t.Parallel()
	if err := Write(failingWriter{}, []byte("safe")); err == nil {
		t.Fatal("safe output accepted writer failure")
	}
	if err := Write(&countingFailureWriter{failure: 2}, []byte("safe")); err == nil {
		t.Fatal("final line feed accepted writer failure")
	}
	if err := Write(failingWriter{}, []byte{'\x00'}); err == nil {
		t.Fatal("escaped output accepted writer failure")
	}
	if err := Write(failingWriter{}, bytes.Repeat([]byte{'\x00'}, escapeBufferBytes)); err == nil {
		t.Fatal("buffered escaped output accepted writer failure")
	}
	if err := Write(failingWriter{}, bytes.Repeat([]byte{'\x00'}, escapeBufferBytes/escapedByteBytes)); err == nil {
		t.Fatal("final line feed flush accepted writer failure")
	}
	prefixFlush := append(bytes.Repeat([]byte{'a'}, escapeBufferBytes-1), []byte("\n::warning::value")...)
	if err := Write(failingWriter{}, prefixFlush); err == nil {
		t.Fatal("workflow prefix flush accepted writer failure")
	}
	finalLineFlush := append([]byte("::"), bytes.Repeat([]byte{'a'}, escapeBufferBytes-3)...)
	if err := Write(failingWriter{}, finalLineFlush); err == nil {
		t.Fatal("final line flush accepted writer failure")
	}
	if err := (&renderer{}).flush(); err != nil {
		t.Fatalf("empty flush = %v", err)
	}
}

func TestWriteAllocationBounds(t *testing.T) {
	safeSource := []byte("safe output\n")
	unsafeSource := []byte("::warning::value\x1b\n")
	safe := testing.AllocsPerRun(1_000, func() {
		writeResult = Write(io.Discard, safeSource)
	})
	unsafe := testing.AllocsPerRun(1_000, func() {
		writeResult = Write(io.Discard, unsafeSource)
	})
	diagnostic := testing.AllocsPerRun(1_000, func() {
		diagnosticResult = Diagnostic("failure\n")
	})
	if writeResult != nil || diagnosticResult == "" || safe != 0 || unsafe != 1 || diagnostic != 1 {
		t.Fatalf("allocations = (safe %.0f, unsafe %.0f, diagnostic %.0f, %v)", safe, unsafe, diagnostic, writeResult)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failure") }

type countingFailureWriter struct {
	calls   int
	failure int
}

func (writer *countingFailureWriter) Write(value []byte) (int, error) {
	writer.calls++
	if writer.calls == writer.failure {
		return 0, errors.New("write failure")
	}
	return len(value), nil
}
