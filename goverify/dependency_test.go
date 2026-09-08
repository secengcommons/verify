package goverify

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
)

func TestCheckModuleCurrency(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	current := moduleList(
		`{"Path":"example.test/root","Main":true}`,
		`{"Path":"example.test/dependency","Version":"v1.0.0","Indirect":true}`,
	)
	runner := dependencyRunner(t, root, filepath.Join(root, "module"), current)
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{Directory: "module", Production: true}, runner); err != nil {
		t.Fatal(err)
	}
	outdated := moduleList(
		`{"Path":"example.test/root","Main":true}`,
		`{"Path":"example.test/dependency","Version":"v1.0.0","Indirect":true,"Update":{"Path":"example.test/dependency","Version":"v1.1.0"}}`,
	)
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{Directory: "module", Production: true}, dependencyRunner(t, root, filepath.Join(root, "module"), outdated)); err != nil {
		t.Fatalf("transitive update error = %v", err)
	}
}

func TestCheckModuleCurrencySelectsDeclaredTools(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	source := moduleList(
		`{"Path":"example.test/tools","Main":true}`,
		`{"Path":"example.test/tool","Version":"v1.0.0","Indirect":true,"Update":{"Path":"example.test/tool","Version":"v1.1.0"}}`,
		`{"Path":"example.test/transitive","Version":"v1.0.0","Indirect":true,"Update":{"Path":"example.test/transitive","Version":"v1.1.0"}}`,
	)
	module := Module{Tools: []string{"example.test/tool/cmd/check"}}
	if err := checkModuleCurrencyWith(t.Context(), root, tool, module, dependencyRunner(t, root, root, source)); !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("tool update error = %v", err)
	}
	module.Tools = nil
	if err := checkModuleCurrencyWith(t.Context(), root, tool, module, dependencyRunner(t, root, root, source)); err != nil {
		t.Fatalf("transitive update error = %v", err)
	}
}

func TestCheckModuleCurrencyRejectsDirectUpdate(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	current := moduleList(
		`{"Path":"example.test/root","Main":true}`,
		`{"Path":"example.test/dependency","Version":"v1.0.0"}`,
	)
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{}, dependencyRunner(t, root, root, current)); err != nil {
		t.Fatalf("current direct dependency error = %v", err)
	}
	source := moduleList(
		`{"Path":"example.test/root","Main":true}`,
		`{"Path":"example.test/dependency","Version":"v1.0.0","Update":{"Path":"example.test/dependency","Version":"v1.1.0"}}`,
	)
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{}, dependencyRunner(t, root, root, source)); !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("direct update error = %v", err)
	}
}

func TestCheckModuleCurrencyRejectsRetractionWithoutUpdate(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	source := moduleList(
		`{"Path":"example.test/root","Main":true}`,
		`{"Path":"example.test/dependency","Version":"v1.0.0","Retracted":["severe defect"]}`,
	)
	err := checkModuleCurrencyWith(t.Context(), root, tool, Module{Production: true}, dependencyRunner(t, root, root, source))
	if !errors.Is(err, ErrDependencyCurrency) || !strings.Contains(err.Error(), "is retracted") {
		t.Fatalf("retracted dependency error = %v", err)
	}
}

func TestDependencyCurrencyRejectsInvalidMaterial(t *testing.T) {
	for _, source := range [][]byte{
		nil,
		[]byte(`{"Path":"example.test/root","Main":true}{`),
		moduleList(`{"Path":"example.test/root","Main":true}`, `{"Path":"example.test/root","Version":"v1.0.0"}`),
		moduleList(`{"Path":"example.test/one","Main":true}`, `{"Path":"example.test/two","Main":true}`),
		moduleList(`{"Path":"example.test/root","Main":true}`, `{"Path":"example.test/dependency","Version":"v1.0.0","Update":{"Path":"other.test/dependency","Version":"v1.1.0"}}`),
	} {
		if _, err := decodeDependencyModules(source); !errors.Is(err, ErrDependencyCurrency) {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
	modules, err := decodeDependencyModules(moduleList(`{"Path":"example.test/root","Main":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dependencyToolOwners(modules, []string{"missing.test/tool/cmd/check"}); !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("missing tool error = %v", err)
	}
	if validDependencyModule(dependencyModule{Path: "example.test/dependency"}) {
		t.Fatal("versionless dependency accepted")
	}
}

func TestCheckModuleCurrencyRejectsOperationFailures(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	failure := errors.New("run")
	failed := func(context.Context, proctree.Command) (proctree.Result, error) { return proctree.Result{}, failure }
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{}, failed); !errors.Is(err, failure) || !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("run error = %v", err)
	}
	if err := checkModuleCurrencyWith(t.Context(), root, tool, Module{}, dependencyRunner(t, root, root, []byte("{"))); !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("decode error = %v", err)
	}
	source := moduleList(`{"Path":"example.test/root","Main":true}`)
	module := Module{Tools: []string{"missing.test/tool/cmd/check"}}
	if err := checkModuleCurrencyWith(t.Context(), root, tool, module, dependencyRunner(t, root, root, source)); !errors.Is(err, ErrDependencyCurrency) {
		t.Fatalf("tool ownership error = %v", err)
	}
}

func TestCheckModuleCurrencyObservesCancellationAfterDecoding(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	ctx := &stagedContext{Context: t.Context(), failAt: 2}
	source := moduleList(`{"Path":"example.test/root","Main":true}`)
	err := checkModuleCurrencyWith(ctx, root, tool, Module{}, dependencyRunner(t, root, root, source))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-decode cancellation error = %v", err)
	}
}

func TestCheckModuleCurrencyRejectsInvalidPublicRequests(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	for _, test := range []struct {
		ctx    context.Context
		root   string
		module Module
	}{
		{ctx: nilContext(), root: root},
		{ctx: t.Context(), root: "relative"},
		{ctx: t.Context(), root: root, module: Module{Directory: "../escape"}},
		{ctx: t.Context(), root: root, module: Module{Directory: strings.Repeat("d", MaxFuzzPathBytes+1)}},
		{ctx: t.Context(), root: root, module: Module{Tools: []string{"invalid\ntool"}}},
	} {
		if err := CheckModuleCurrency(test.ctx, test.root, tool, test.module); !errors.Is(err, ErrDependencyCurrency) {
			t.Fatalf("request %#v error = %v", test, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := CheckModuleCurrency(cancelled, root, tool, Module{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request error = %v", err)
	}
}

func dependencyRunner(t *testing.T, root, moduleRoot string, source []byte) repositoryModuleRunner {
	t.Helper()
	return func(_ context.Context, command proctree.Command) (proctree.Result, error) {
		wantArguments := []string{"-C", moduleRoot, "list", "-m", "-u", "-json", "all"}
		if command.Directory != root || !reflect.DeepEqual(command.Arguments, wantArguments) ||
			!slices.Contains(command.Environment, "GOFLAGS=-mod=readonly") {
			t.Fatalf("command = %#v", command)
		}
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: source}, nil
	}
}

func moduleList(values ...string) []byte {
	result := make([]byte, 0)
	for _, value := range values {
		result = append(result, value...)
		result = append(result, '\n')
	}
	return result
}

func FuzzDependencyModules(f *testing.F) {
	f.Add(moduleList(`{"Path":"example.test/root","Main":true}`))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxRepositoryCommandBytes {
			return
		}
		first, firstErr := decodeDependencyModules(source)
		second, secondErr := decodeDependencyModules(source)
		if !reflect.DeepEqual(first, second) || (firstErr == nil) != (secondErr == nil) ||
			errors.Is(firstErr, ErrDependencyCurrency) != errors.Is(secondErr, ErrDependencyCurrency) {
			t.Fatal("dependency decoding differs")
		}
	})
}
