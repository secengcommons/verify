package goverify

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var benchmarkRepositoryFiles repositoryFiles
var benchmarkRepository Repository
var benchmarkCoverage Coverage
var benchmarkWorkflowReferences []WorkflowReference
var benchmarkWorkflowTags map[string]actionTag
var benchmarkFuzzNames []string
var benchmarkNames []string

const benchmarkRepositorySourceFiles = 64

func BenchmarkRepositoryFileDiscovery(b *testing.B) {
	root := b.TempDir()
	writeBenchmarkFile(b, root, "go.mod", "module benchmark.test/repository\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeBenchmarkFile(b, root, ".golangci.yml", "version: '2'\n")
	for index := range benchmarkRepositorySourceFiles {
		writeBenchmarkFile(b, root, fmt.Sprintf("internal/p%d/value.go", index), "package value\n")
	}
	b.ResetTimer()
	for b.Loop() {
		files, err := discoverRepositoryFiles(b.Context(), root)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkRepositoryFiles = files
	}
}

func BenchmarkRepositoryConstruction(b *testing.B) {
	modules := []RepositoryModule{
		{Directory: ".", Path: "benchmark.test/repository", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
		{Directory: "tools", Path: "benchmark.test/repository/tools", GoVersion: "1.26.0", Toolchain: "go1.26.6", Tools: []string{"benchmark.test/check/cmd/check"}},
	}
	base := Repository{ID: "benchmark", Self: "self", LinterConfig: ".golangci.yml"}
	for b.Loop() {
		repository, err := RepositoryFromModules(modules, base)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkRepository = repository
	}
}

func BenchmarkCoverageCheck(b *testing.B) {
	profile := []byte("mode: atomic\nbenchmark.test/value.go:1.1,1.2 1 1\nbenchmark.test/value.go:2.1,2.2 2 3\n")
	for b.Loop() {
		coverage, err := CheckCoverage(bytes.NewReader(profile))
		if err != nil {
			b.Fatal(err)
		}
		benchmarkCoverage = coverage
	}
}

func BenchmarkWorkflowInspection(b *testing.B) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	source := []byte("jobs:\n  build:\n    container: registry.test/build@sha256:" + digest + "\n    services:\n      database:\n        image: registry.test/database@sha256:" + digest + "\n    steps:\n      - uses: actions/checkout@" + commit + "\n")
	for b.Loop() {
		references, err := InspectWorkflowReferences(source)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkWorkflowReferences = references
	}
}

func BenchmarkWorkflowAliasInspection(b *testing.B) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	source := []byte("jobs:\n  build: &build\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + commit + " # v7.0.1\n  copy: *build\n")
	for b.Loop() {
		references, err := InspectWorkflowReferences(source)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkWorkflowReferences = references
	}
}

func BenchmarkLocalActionInspection(b *testing.B) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	source := []byte("name: check\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + commit + " # v7.0.1\n")
	for b.Loop() {
		references, err := inspectLocalActionReferences(source)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkWorkflowReferences = references
	}
}

func BenchmarkWorkflowCurrency(b *testing.B) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	source := []byte("1123456789abcdef0123456789abcdef01234567\trefs/tags/v6.0.0\n" +
		commit + "\trefs/tags/v7.0.1\n")
	reference := WorkflowReference{
		Kind: WorkflowAction, Value: "actions/checkout@" + commit, Version: "v7.0.1",
	}
	for b.Loop() {
		tags, err := parseActionTags(source)
		if err != nil {
			b.Fatal(err)
		}
		if err = verifyActionReference(reference, tags); err != nil {
			b.Fatal(err)
		}
		benchmarkWorkflowTags = tags
	}
}

func BenchmarkTargetInspection(b *testing.B) {
	source := []byte("package benchmark\nimport \"testing\"\nfunc FuzzValue(*testing.F) {}\nfunc BenchmarkValue(*testing.B) {}\n")
	for b.Loop() {
		fuzz, benchmarks, err := testTargetNames("value_test.go", source)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkFuzzNames = fuzz
		benchmarkNames = benchmarks
	}
}

func writeBenchmarkFile(b *testing.B, root, name, source string) {
	b.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		b.Fatal(err)
	}
}
