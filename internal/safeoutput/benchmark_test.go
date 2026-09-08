package safeoutput

import (
	"bytes"
	"io"
	"testing"
)

var benchmarkWriteError error
var benchmarkDiagnostic string

const benchmarkLines = 256

func BenchmarkWriteSafe(benchmark *testing.B) {
	source := bytes.Repeat([]byte("ordinary output\n"), benchmarkLines)
	benchmark.SetBytes(int64(len(source)))
	benchmark.ReportAllocs()
	for benchmark.Loop() {
		benchmarkWriteError = Write(io.Discard, source)
	}
	if benchmarkWriteError != nil {
		benchmark.Fatal(benchmarkWriteError)
	}
}

func BenchmarkWriteEscaped(benchmark *testing.B) {
	source := bytes.Repeat([]byte("::warning::value\x1b\n"), benchmarkLines)
	benchmark.SetBytes(int64(len(source)))
	benchmark.ReportAllocs()
	for benchmark.Loop() {
		benchmarkWriteError = Write(io.Discard, source)
	}
	if benchmarkWriteError != nil {
		benchmark.Fatal(benchmarkWriteError)
	}
}

func BenchmarkDiagnostic(benchmark *testing.B) {
	source := "failure\n::warning::value\x1b"
	benchmark.ReportAllocs()
	for benchmark.Loop() {
		benchmarkDiagnostic = Diagnostic(source)
	}
}
