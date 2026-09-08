package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

const repositoryOperationTimeout = 5 * time.Minute

func operationReader[O, M any](t *testing.T, operation string, owner O, material M) *bytes.Reader {
	t.Helper()
	encoded, err := repositoryop.Encode(operation, repositoryop.Specification[O, M]{Owner: owner, Material: material})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encoded)
}

func TestClassifyRepositoryOperation(t *testing.T) {
	tests := []struct {
		arguments []string
		operation repositoryOperation
		found     bool
	}{
		{arguments: []string{"__go-coverage-self-test"}, operation: repositoryCoverageSelfTest, found: true},
		{arguments: []string{"__go-fuzz-inventory"}, operation: repositoryFuzzInventory, found: true},
		{arguments: []string{"__go-fuzz-campaign"}, operation: repositoryFuzzCampaign, found: true},
		{arguments: []string{"__go-workflow-admission"}, operation: repositoryWorkflowAdmission, found: true},
		{arguments: []string{"__go-workflow-dependencies"}, operation: repositoryWorkflowDependencies, found: true},
		{arguments: []string{"__go-module-currency"}, operation: repositoryModuleCurrency, found: true},
		{arguments: []string{"__go-compile:1"}, operation: repositoryCompile, found: true},
		{arguments: []string{"__go-benchmark"}, operation: repositoryBenchmark, found: true},
		{arguments: []string{"__go-coverage"}},
		{arguments: []string{"__go-coverage:2"}, operation: repositoryCoverage, found: true},
		{arguments: []string{"__go-coverage:"}},
		{arguments: []string{"__go-coverage:02"}},
		{arguments: []string{"__go-coverage:invalid"}},
		{arguments: []string{"unknown"}},
		{arguments: nil},
		{arguments: []string{"__go-coverage", "extra"}},
	}
	for _, test := range tests {
		operation, found := classifyRepositoryOperation(test.arguments)
		if operation != test.operation || found != test.found {
			t.Fatalf("operation %#v = (%d, %t)", test.arguments, operation, found)
		}
	}
}

func TestRunRepositoryOperationFailures(t *testing.T) {
	root := t.TempDir()
	if err := runRepositoryOperation(t.Context(), root, repositoryOperation(255), "unknown", strings.NewReader("{}"), io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("unknown operation error = %v", err)
	}
	for _, operation := range []repositoryOperation{
		repositoryCoverageSelfTest, repositoryFuzzInventory, repositoryFuzzCampaign,
		repositoryCoverage, repositoryWorkflowAdmission, repositoryWorkflowDependencies, repositoryModuleCurrency,
		repositoryCompile, repositoryBenchmark,
	} {
		if err := runRepositoryOperation(t.Context(), root, operation, "wrong", strings.NewReader("{}"), io.Discard); !errors.Is(err, verify.ErrInvalidPlan) {
			t.Fatalf("operation %d error = %v", operation, err)
		}
	}
}

func TestRunInternalRejectsInvalidOwners(t *testing.T) {
	if code, handled := runInternal(nilContext(), t.TempDir(), []string{"__go-coverage-self-test"}, strings.NewReader(""), io.Discard, io.Discard); !handled || code != exitInvocation {
		t.Fatalf("nil context = (%d, %t)", code, handled)
	}
	if code, handled := runInternal(context.Background(), t.TempDir(), []string{"__go-coverage-self-test"}, strings.NewReader(""), nil, io.Discard); !handled || code != exitInvocation {
		t.Fatalf("nil output = (%d, %t)", code, handled)
	}
	if code, handled := runInternal(context.Background(), t.TempDir(), []string{"__go-coverage-self-test"}, nil, io.Discard, io.Discard); !handled || code != exitInvocation {
		t.Fatalf("nil input = (%d, %t)", code, handled)
	}
}

func repositoryOperationFixture(t *testing.T) (string, goverify.Tool) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/operation\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "value.go"), []byte("package operation\nfunc Value() int { return 1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := "package operation\nimport \"testing\"\nfunc TestValue(t *testing.T) { if Value() != 1 { t.Fatal(Value()) } }\n" +
		"func FuzzValue(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, value int) {}) }\n" +
		"func BenchmarkValue(b *testing.B) {}\n"
	if err := os.WriteFile(filepath.Join(root, "operation_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := goTool()
	if err != nil {
		t.Fatal(err)
	}
	environment := goverify.ReplaceEnvironment(selectedEnvironment(), "GOTOOLCHAIN", "local")
	tool := goverify.Tool{Executable: executable, Environment: environment, Timeout: repositoryOperationTimeout, OutputLimit: 1 << 20}
	return root, tool
}

func TestRunRepositoryCompilationOperations(t *testing.T) {
	root, tool := repositoryOperationFixture(t)
	if err := runRepositoryOperation(t.Context(), root, repositoryModuleCurrency, "__go-module-currency",
		operationReader(t, "__go-module-currency", tool, []goverify.Module(nil)), io.Discard); err != nil {
		t.Fatalf("empty module currency operation = %v", err)
	}
	module := goverify.Module{Name: "Root", Packages: []string{"./..."}, Production: true}
	if err := runRepositoryOperation(t.Context(), root, repositoryCompile, "__go-compile:0",
		operationReader(t, "__go-compile:0", tool, module), io.Discard); err != nil {
		t.Fatalf("compile operation = %v", err)
	}
}

func TestRunRepositoryTestOperations(t *testing.T) {
	root, tool := repositoryOperationFixture(t)
	var output bytes.Buffer
	scope := goverify.TestScope{Name: "Root", Packages: []string{"./..."}}
	if err := runRepositoryOperation(t.Context(), root, repositoryCoverage, "__go-coverage:0",
		operationReader(t, "__go-coverage:0", tool, scope), &output); err != nil || output.Len() == 0 {
		t.Fatalf("coverage operation = (%q, %v)", output.String(), err)
	}
	output.Reset()
	campaign := goverify.Campaign{Go: tool, Duration: "1x", Parallelism: 1, Jobs: 1}
	targets := []goverify.FuzzTarget{{Module: "example.test/operation", Package: "example.test/operation", Name: "FuzzValue", Directory: ".", Argument: "."}}
	err := runRepositoryOperation(t.Context(), root, repositoryFuzzCampaign, "__go-fuzz-campaign",
		operationReader(t, "__go-fuzz-campaign", campaign, targets), &output)
	if !fuzzAvailable() && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil || output.Len() == 0 {
		t.Fatalf("fuzz operation = (%q, %v)", output.String(), err)
	}
}

func TestCoverageOperationCannotRebindScope(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/root\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootTest := "package root\nimport (\"os\"; \"testing\")\nfunc TestMain(m *testing.M) { _ = os.WriteFile(\"root-executed\", nil, 0o600); os.Exit(m.Run()) }\n"
	if err := os.WriteFile(filepath.Join(root, "root_test.go"), []byte(rootTest), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "go.mod"), []byte("module example.test/nested\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "value.go"), []byte("package nested\nfunc Value() int { return 1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nestedTest := "package nested\nimport \"testing\"\nfunc TestValue(t *testing.T) { if Value() != 1 { t.Fatal(Value()) } }\n"
	if err := os.WriteFile(filepath.Join(nested, "value_test.go"), []byte(nestedTest), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := goTool()
	if err != nil {
		t.Fatal(err)
	}
	tool := goverify.Tool{
		Executable: executable, Environment: goverify.ReplaceEnvironment(selectedEnvironment(), "GOTOOLCHAIN", "local"),
		Timeout: repositoryOperationTimeout, OutputLimit: 1 << 20,
	}
	scope := goverify.TestScope{Directory: "nested", Name: "Nested", Packages: []string{"./..."}}
	var output bytes.Buffer
	err = runRepositoryOperation(t.Context(), root, repositoryCoverage, "__go-coverage:0",
		operationReader(t, "__go-coverage:0", tool, scope), &output)
	if err != nil || output.Len() == 0 {
		t.Fatalf("nested coverage = (%q, %v)", output.String(), err)
	}
	if _, err = os.Stat(filepath.Join(root, "root-executed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root scope execution evidence = %v", err)
	}
}

func TestRunRepositoryBenchmarkOperation(t *testing.T) {
	root, tool := repositoryOperationFixture(t)
	var output bytes.Buffer
	benchmarks := []goverify.BenchmarkTarget{{
		Module: "example.test/operation", Package: "example.test/operation", Name: "BenchmarkValue", Directory: ".", Argument: ".",
	}}
	if err := runRepositoryOperation(t.Context(), root, repositoryBenchmark, "__go-benchmark",
		operationReader(t, "__go-benchmark", tool, benchmarks), &output); err != nil || output.Len() == 0 {
		t.Fatalf("benchmark operation = (%q, %v)", output.String(), err)
	}
}

func TestRunWorkflowAdmissionOperation(t *testing.T) {
	root := t.TempDir()
	workflow := ".github/workflows/core.yml"
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(workflow)), []byte("jobs: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRepositoryOperation(t.Context(), root, repositoryWorkflowAdmission, "__go-workflow-admission",
		operationReader(t, "__go-workflow-admission", struct{}{}, []string{workflow}), io.Discard); err != nil {
		t.Fatalf("workflow admission operation = %v", err)
	}
	if err := runRepositoryOperation(t.Context(), root, repositoryWorkflowDependencies, "__go-workflow-dependencies",
		operationReader(t, "__go-workflow-dependencies", goverify.Tool{}, []string{workflow}), io.Discard); !errors.Is(err, goverify.ErrWorkflowCurrency) {
		t.Fatalf("workflow dependency operation = %v", err)
	}
}

func TestRunModuleCurrencyOperationFailure(t *testing.T) {
	root := t.TempDir()
	tool := goverify.Tool{Executable: "relative"}
	modules := []goverify.Module{{Name: "Root"}}
	err := runRepositoryOperation(t.Context(), root, repositoryModuleCurrency, "__go-module-currency",
		operationReader(t, "__go-module-currency", tool, modules), io.Discard)
	if !errors.Is(err, goverify.ErrDependencyCurrency) {
		t.Fatalf("module currency operation = %v", err)
	}
}

func TestRunCoverageSelfTestRejectsBrokenChecker(t *testing.T) {
	if err := runCoverageSelfTestWith(func(io.Reader) (goverify.Coverage, error) { return goverify.Coverage{}, nil }); err == nil {
		t.Fatal("coverage self-test accepted invalid success")
	}
	calls := 0
	err := runCoverageSelfTestWith(func(io.Reader) (goverify.Coverage, error) {
		calls++
		if calls == 1 {
			return goverify.Coverage{}, goverify.ErrIncompleteCoverage
		}
		if calls == 2 {
			return goverify.Coverage{}, goverify.ErrCoverageProfile
		}
		return goverify.Coverage{}, errors.New("complete failure")
	})
	if err == nil {
		t.Fatal("coverage self-test accepted complete failure")
	}
}
