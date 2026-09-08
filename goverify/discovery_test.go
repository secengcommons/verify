package goverify

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

func TestDiscoverRepository(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, "value.go", "package root\n")
	writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
	writeDiscoveryFile(t, root, "tools/go.mod", "module example.test/root/tools\n\ngo 1.25.0\ntoolchain go1.26.6\n\ntool example.test/tool/cmd/check\n\nrequire example.test/tool v0.0.0\n")
	writeDiscoveryFile(t, root, "tools/workflow/go.mod", "module example.test/root/tools/workflow\n\ngo 1.26.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, "tools/workflow/check.go", "package workflow\n")
	writeDiscoveryFile(t, root, ".github/scripts/check.sh", "#!/bin/sh\n")
	writeDiscoveryFile(t, root, ".github/workflows/core.yml", "name: Core\n")
	writeDiscoveryFile(t, root, "testdata/ignored/go.mod", "module ignored.test/testdata\n\ngo 1.24.0\n")
	writeDiscoveryFile(t, root, "vendor/ignored/go.mod", "module ignored.test/vendor\n\ngo 1.24.0\n")
	writeDiscoveryFile(t, root, ".hidden/go.mod", "module ignored.test/hidden\n\ngo 1.24.0\n")

	inventory, err := DiscoverRepository(t.Context(), root, discoveryGoTool(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []RepositoryModule{
		{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
		{Directory: "tools", Path: "example.test/root/tools", GoVersion: "1.25.0", Toolchain: "go1.26.6", Tools: []string{"example.test/tool/cmd/check"}},
		{Directory: "tools/workflow", Path: "example.test/root/tools/workflow", GoVersion: "1.26.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
	}
	if !reflect.DeepEqual(inventory.Modules, want) {
		t.Fatalf("modules = %#v", inventory.Modules)
	}
	if inventory.LinterConfig != ".golangci.yml" || !reflect.DeepEqual(inventory.ShellFiles, []string{".github/scripts/check.sh"}) ||
		!reflect.DeepEqual(inventory.WorkflowFiles, []string{".github/workflows/core.yml"}) {
		t.Fatalf("inventory = (%#v, %v)", inventory, err)
	}
}

func TestDiscoverRepositoryRejectsInvalidInventory(t *testing.T) {
	goTool := discoveryGoTool(t)
	for _, test := range []struct {
		name  string
		files map[string]string
	}{
		{name: "missing root", files: map[string]string{"value.go": "package value\n"}},
		{name: "missing toolchain", files: map[string]string{"go.mod": "module example.test/root\n\ngo 1.24.0\n"}},
		{name: "duplicate module", files: map[string]string{
			"go.mod":        "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n",
			"nested/go.mod": "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n",
		}},
		{name: "newer floor", files: map[string]string{"go.mod": "module example.test/root\n\ngo 1.27.0\ntoolchain go1.26.6\n"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
			for name, value := range test.files {
				writeDiscoveryFile(t, root, name, value)
			}
			if _, err := DiscoverRepository(t.Context(), root, goTool); !errors.Is(err, ErrRepositoryDiscovery) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDiscoverRepositoryRejectsFilesystemBoundaries(t *testing.T) {
	goTool := discoveryGoTool(t)
	if _, err := DiscoverRepository(nilContext(), t.TempDir(), goTool); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := DiscoverRepository(t.Context(), ".", goTool); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("relative root error = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := DiscoverRepository(t.Context(), missing, goTool); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("missing root error = %v", err)
	}
	for _, files := range []map[string]string{
		{".golangci.yml": "version: '2'\n"},
		{"go.mod": "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n"},
		{
			"go.mod":         "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n",
			".golangci.yml":  "version: '2'\n",
			".golangci.yaml": "version: '2'\n",
		},
	} {
		root := t.TempDir()
		for name, source := range files {
			writeDiscoveryFile(t, root, name, source)
		}
		if _, err := DiscoverRepository(t.Context(), root, goTool); !errors.Is(err, ErrRepositoryDiscovery) {
			t.Fatalf("files %#v error = %v", files, err)
		}
	}
}

func TestRepositoryFileInventoryBounds(t *testing.T) {
	owner := repositoryFileInventory{ctx: t.Context(), directories: make([]string, MaxRepositoryModules)}
	if err := owner.addModule("extra"); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("module bound error = %v", err)
	}
	files := make([]string, MaxRepositorySources)
	bytes := 0
	if err := addRepositorySource(&files, &bytes, "value"); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("source count error = %v", err)
	}
	files = nil
	bytes = MaxRepositorySourceBytes
	if err := addRepositorySource(&files, &bytes, "value"); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("source byte error = %v", err)
	}
	owner = repositoryFileInventory{ctx: t.Context(), linterConfig: ".golangci.yml"}
	if err := owner.addSourceFile(".", ".golangci.yaml"); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("duplicate linter error = %v", err)
	}
	owner = repositoryFileInventory{ctx: t.Context(), shellFiles: make([]string, MaxRepositorySources)}
	if err := owner.addSourceFile(".", "check.sh"); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("shell source error = %v", err)
	}
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	owner = repositoryFileInventory{ctx: t.Context(), root: opened, directories: make([]string, MaxRepositoryModules)}
	if err = owner.walk("."); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("walk module bound error = %v", err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryFileInventoryRejectsEntryBounds(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "one", "one")
	writeDiscoveryFile(t, root, "two", "two")
	opened := openRepositoryRoot(t, root)
	owner := repositoryFileInventory{ctx: t.Context(), root: opened, entries: MaxRepositoryEntries - 1}
	if _, err := owner.readDirectory("."); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("entry bound error = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	opened = openRepositoryRoot(t, root)
	owner = repositoryFileInventory{ctx: t.Context(), root: opened, entries: MaxRepositoryEntries + 1}
	if _, err := owner.readDirectory("."); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("exhausted inventory error = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryFileInventoryReadsEmptyAndCancelledDirectories(t *testing.T) {
	empty := t.TempDir()
	opened := openRepositoryRoot(t, empty)
	owner := repositoryFileInventory{ctx: t.Context(), root: opened}
	if entries, err := owner.readDirectory("."); err != nil || len(entries) != 0 {
		t.Fatalf("empty directory = (%d, %v)", len(entries), err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	opened = openRepositoryRoot(t, empty)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	owner = repositoryFileInventory{ctx: cancelled, root: opened}
	if _, err := owner.readDirectory("."); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedDirectoryConsumesAndSortsPartialReads(t *testing.T) {
	source := &partialDirectory{reads: []directoryRead{
		{entries: []os.DirEntry{fixtureDirEntry{name: "z"}}},
		{entries: []os.DirEntry{fixtureDirEntry{name: "a"}}, err: io.EOF},
	}}
	entries, err := readBoundedDirectory(t.Context(), source.ReadDir, source.Close, 2, ErrRepositoryDiscovery)
	if err != nil || !source.closed || len(entries) != 2 || entries[0].Name() != "a" || entries[1].Name() != "z" {
		t.Fatalf("directory = (%v, closed %t, %v)", entryNames(entries), source.closed, err)
	}
}

func TestBoundedDirectoryRejectsIncompleteOrExcessReads(t *testing.T) {
	failure := errors.New("read")
	for _, source := range []*partialDirectory{
		{reads: []directoryRead{{entries: []os.DirEntry{fixtureDirEntry{name: "a"}}, err: failure}}},
		{reads: []directoryRead{{}}},
		{reads: []directoryRead{{entries: []os.DirEntry{fixtureDirEntry{name: "a"}, fixtureDirEntry{name: "b"}}, err: io.EOF}}},
	} {
		if _, err := readBoundedDirectory(t.Context(), source.ReadDir, source.Close, 1, ErrRepositoryDiscovery); !errors.Is(err, ErrRepositoryDiscovery) || !source.closed {
			t.Fatalf("directory error = %v, closed = %t", err, source.closed)
		}
	}
	source := &partialDirectory{reads: []directoryRead{{err: io.EOF}}, closeErr: failure}
	if _, err := readBoundedDirectory(t.Context(), source.ReadDir, source.Close, 1, ErrRepositoryDiscovery); !errors.Is(err, failure) {
		t.Fatalf("directory close error = %v", err)
	}
}

type directoryRead struct {
	entries []os.DirEntry
	err     error
}

type partialDirectory struct {
	reads    []directoryRead
	index    int
	closed   bool
	closeErr error
}

func (source *partialDirectory) ReadDir(int) ([]os.DirEntry, error) {
	if source.index == len(source.reads) {
		return nil, io.EOF
	}
	result := source.reads[source.index]
	source.index++
	return result.entries, result.err
}

func (source *partialDirectory) Close() error {
	source.closed = true
	return source.closeErr
}

func entryNames(entries []os.DirEntry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.Name()
	}
	return result
}

func TestRepositoryFileInventoryRejectsClosedAndSpecialEntries(t *testing.T) {
	opened := openRepositoryRoot(t, t.TempDir())
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	owner := repositoryFileInventory{ctx: t.Context(), root: opened}
	if _, err := owner.readDirectory("."); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("closed root error = %v", err)
	}
	if err := owner.walk("."); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("walk read error = %v", err)
	}
	if err := owner.walkEntry(".", fixtureDirEntry{name: "pipe", mode: os.ModeNamedPipe}); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("special file error = %v", err)
	}
	if err := owner.walkEntry(".", fixtureDirEntry{name: strings.Repeat("p", MaxFuzzPathBytes+1)}); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("path bound error = %v", err)
	}
	if err := owner.walkEntry(".", fixtureDirEntry{name: "invalid\nname"}); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("invalid name error = %v", err)
	}
}

func openRepositoryRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	opened, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

func TestDiscoverRepositoryRejectsCancellationAndCommandFailure(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DiscoverRepository(cancelled, root, discoveryGoTool(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	tool := discoveryGoTool(t)
	tool.Executable = filepath.Join(root, "missing-go")
	if _, err := DiscoverRepository(t.Context(), root, tool); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("command error = %v", err)
	}
}

func TestDiscoverRepositoryObservesCancellationAfterModuleInspection(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
	writeDiscoveryFile(t, root, "nested/go.mod", "module example.test/nested\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	ctx, cancel := context.WithCancel(t.Context())
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		cancel()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: []byte(`{"Module":{"Path":"example.test/root"},"Go":"1.24.0","Toolchain":"go1.26.6"}`)}, nil
	}
	if _, err := discoverRepositoryWith(ctx, root, discoveryGoTool(t), runner); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestDiscoverRepositoryObservesCancellationBeforePackageClassification(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
	writeDiscoveryFile(t, root, "value.go", "package root\n")
	ctx := &delayedCancellationContext{Context: t.Context()}
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		ctx.armed = true
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: []byte(`{"Module":{"Path":"example.test/root"},"Go":"1.24.0","Toolchain":"go1.26.6"}`)}, nil
	}
	if _, err := discoverRepositoryWith(ctx, root, discoveryGoTool(t), runner); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

type delayedCancellationContext struct {
	context.Context
	armed bool
	seen  bool
}

func (ctx *delayedCancellationContext) Err() error {
	if !ctx.armed {
		return nil
	}
	if !ctx.seen {
		ctx.seen = true
		return nil
	}
	return context.Canceled
}

func TestRepositoryInventoryRejectsSymlinkEntry(t *testing.T) {
	owner := repositoryFileInventory{ctx: t.Context()}
	if err := owner.walkEntry(".", fixtureDirEntry{name: "linked", mode: os.ModeSymlink}); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("error = %v", err)
	}
}

func TestRepositoryInventoryObservesCancellationBetweenEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	owner := repositoryFileInventory{ctx: ctx}
	if err := owner.walkEntry(".", fixtureDirEntry{name: "value.go"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if err := owner.walk("."); !errors.Is(err, context.Canceled) {
		t.Fatalf("walk error = %v", err)
	}
	root := t.TempDir()
	writeDiscoveryFile(t, root, "value", "value")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedContext{Context: t.Context(), failAt: 4}
	owner = repositoryFileInventory{ctx: staged, root: opened}
	if err = owner.walk("."); !errors.Is(err, context.Canceled) {
		t.Fatalf("between entries error = %v", err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
}

type stagedContext struct {
	context.Context
	calls  int
	failAt int
}

func (ctx *stagedContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.failAt {
		return context.Canceled
	}
	return nil
}

func discoveryGoTool(t *testing.T) Tool {
	t.Helper()
	executable := "go"
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		t.Fatal(err)
	}
	environment := []string{"GOTOOLCHAIN=auto", "GOWORK=off"}
	for _, name := range []string{"HOME", "LOCALAPPDATA", "PATH", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"} {
		if value, found := os.LookupEnv(name); found {
			environment = append(environment, name+"="+value)
		}
	}
	return Tool{Executable: path, Environment: environment, Timeout: verify.MaxTimeout, OutputLimit: MaxRepositoryCommandBytes}
}

func writeDiscoveryFile(t *testing.T, root, name, value string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectRepositoryModuleRejectsMalformedOutput(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: verify.MaxTimeout, OutputLimit: MaxRepositoryCommandBytes}
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, ExitCode: 0, Outcome: proctree.OutcomeCompleted, Stdout: []byte("{}{}")}, nil
	}
	if _, err := inspectRepositoryModule(t.Context(), root, ".", tool, runner); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("error = %v", err)
	}
	runner = func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, ExitCode: 0, Outcome: proctree.OutcomeCompleted, Stdout: []byte("{")}, nil
	}
	if _, err := inspectRepositoryModule(t.Context(), root, ".", tool, runner); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("decode error = %v", err)
	}
}

func TestInspectRepositoryModuleRejectsCommandOutcomes(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: verify.MaxTimeout, OutputLimit: MaxRepositoryCommandBytes}
	for _, outcome := range []struct {
		result proctree.Result
		err    error
	}{
		{},
		{result: proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure}},
		{result: proctree.Result{Started: true, Outcome: proctree.OutcomeCleanupFailure}},
		{result: proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, err: errors.New("run")},
	} {
		runner := func(context.Context, proctree.Command) (proctree.Result, error) { return outcome.result, outcome.err }
		if _, err := inspectRepositoryModule(t.Context(), root, ".", tool, runner); !errors.Is(err, ErrRepositoryDiscovery) {
			t.Fatalf("outcome %#v error = %v", outcome, err)
		}
	}
	diagnostic := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure, Stderr: []byte("invalid module\n")}, nil
	}
	if _, err := inspectRepositoryModule(t.Context(), root, ".", tool, diagnostic); !strings.Contains(err.Error(), "invalid module") {
		t.Fatalf("diagnostic error = %v", err)
	}
	invalidTool := tool
	invalidTool.Executable = "relative"
	if _, err := inspectRepositoryModule(t.Context(), root, ".", invalidTool, func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{}, nil
	}); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("invalid tool error = %v", err)
	}
}

func TestRunRepositoryGoRejectsInvalidOwners(t *testing.T) {
	root := t.TempDir()
	valid := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	for _, test := range []struct {
		ctx       context.Context
		root      string
		directory string
		tool      Tool
	}{
		{ctx: nilContext(), root: root, directory: ".", tool: valid},
		{ctx: t.Context(), root: "relative", directory: ".", tool: valid},
		{ctx: t.Context(), root: filepath.Join(t.TempDir(), "missing"), directory: ".", tool: valid},
		{ctx: t.Context(), root: valid.Executable, directory: ".", tool: valid},
		{ctx: t.Context(), root: root, directory: "../outside", tool: valid},
		{ctx: t.Context(), root: root, directory: ".", tool: Tool{Executable: filepath.Join(root, "missing"), Timeout: valid.Timeout, OutputLimit: valid.OutputLimit}},
		{ctx: t.Context(), root: root, directory: ".", tool: Tool{Executable: valid.Executable, Environment: []string{"INVALID"}, Timeout: valid.Timeout, OutputLimit: valid.OutputLimit}},
		{ctx: t.Context(), root: root, directory: ".", tool: Tool{Executable: valid.Executable, Timeout: verify.MaxTimeout + 1, OutputLimit: valid.OutputLimit}},
		{ctx: t.Context(), root: root, directory: ".", tool: Tool{Executable: valid.Executable, Timeout: valid.Timeout, OutputLimit: verify.MaxOutputBytes + 1}},
	} {
		called := false
		_, err := runRepositoryGo(test.ctx, test.root, test.directory, test.tool,
			func(context.Context, proctree.Command) (proctree.Result, error) {
				called = true
				return proctree.Result{}, nil
			}, "version")
		if !errors.Is(err, ErrRepositoryDiscovery) || called {
			t.Fatalf("owner %#v = (called %t, %v)", test, called, err)
		}
	}
	for _, limit := range []int{0, verify.MaxOutputBytes + 1} {
		called := false
		_, err := runRepositoryGoWithLimit(t.Context(), root, ".", valid, func(context.Context, proctree.Command) (proctree.Result, error) {
			called = true
			return proctree.Result{}, nil
		}, limit, "version")
		if !errors.Is(err, ErrRepositoryDiscovery) || called {
			t.Fatalf("limit %d = (called %t, %v)", limit, called, err)
		}
	}
}

func TestRunRepositoryGoOwnsEnvironment(t *testing.T) {
	root := t.TempDir()
	environment := []string{"VALUE=before"}
	tool := Tool{Executable: testExecutable(t), Environment: environment, Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	runner := func(_ context.Context, command proctree.Command) (proctree.Result, error) {
		environment[0] = "VALUE=after"
		if !reflect.DeepEqual(command.Environment, []string{"VALUE=before"}) {
			t.Fatalf("environment = %#v", command.Environment)
		}
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, nil
	}
	if _, err := runRepositoryGo(t.Context(), root, ".", tool, runner, "version"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRepositoryModulesRejectsEveryIdentityBoundary(t *testing.T) {
	valid := RepositoryModule{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6"}
	invalid := [][]RepositoryModule{
		nil,
		make([]RepositoryModule, MaxRepositoryModules+1),
		{{Directory: "nested", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain}},
		{{Directory: ".", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: "invalid"}},
		{{Directory: ".", Path: "", GoVersion: valid.GoVersion, Toolchain: valid.Toolchain}},
		{{Directory: ".", Path: valid.Path, GoVersion: "invalid", Toolchain: valid.Toolchain}},
		{{Directory: ".", Path: valid.Path, GoVersion: "1.27.0", Toolchain: valid.Toolchain}},
		{{Directory: "../escape", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain}},
		{valid, valid},
		{valid, RepositoryModule{Directory: "nested", Path: "example.test/nested", GoVersion: valid.GoVersion, Toolchain: "invalid"}},
		{{Directory: ".", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain, Tools: []string{"invalid\ntool"}}},
		{{Directory: ".", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain, Tools: []string{"tool", "tool"}}},
		{{Directory: ".", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain, Tools: []string{"tool/z", "tool/a"}}},
		{{Directory: ".", Path: strings.Repeat("m", MaxFuzzPathBytes+1), GoVersion: valid.GoVersion, Toolchain: valid.Toolchain}},
		{{Directory: ".", Path: valid.Path, GoVersion: valid.GoVersion, Toolchain: valid.Toolchain, Tools: []string{strings.Repeat("t", MaxFuzzPathBytes+1)}}},
	}
	for _, modules := range invalid {
		if err := validateRepositoryModules(modules); !errors.Is(err, ErrRepositoryDiscovery) {
			t.Fatalf("modules %#v error = %v", modules, err)
		}
	}
}

func TestValidateRepositoryModulesAcceptsNestedToolchainPreferences(t *testing.T) {
	root := RepositoryModule{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6"}
	for index, toolchain := range []string{"", "default", "go1.25.0", "go1.27.0"} {
		modules := []RepositoryModule{root, {
			Directory: "nested" + strconv.Itoa(index), Path: "example.test/nested" + strconv.Itoa(index),
			GoVersion: "1.24.0", Toolchain: toolchain,
		}}
		if err := validateRepositoryModules(modules); err != nil {
			t.Fatalf("toolchain %q error = %v", toolchain, err)
		}
	}
}

func TestGoCompatibilityVersionBoundaries(t *testing.T) {
	for _, test := range []struct {
		minimum string
		maximum string
	}{
		{minimum: "invalid", maximum: "go1.26.6"},
		{minimum: "go1.24.0", maximum: "invalid"},
		{minimum: "go2.0.0", maximum: "go1.26.6"},
		{minimum: "go1.27.0", maximum: "go1.26.6"},
	} {
		if versions := goCompatibilityVersions(test.minimum, test.maximum); versions != nil {
			t.Fatalf("versions = %#v", versions)
		}
	}
	if versions := goCompatibilityVersions("go1.26.6", "go1.26.6"); versions != nil {
		t.Fatalf("single version = %#v", versions)
	}
	if versions := goCompatibilityVersions("go1.24", "go1.26.6"); !reflect.DeepEqual(versions, []string{"go1.24.0", "go1.25.0"}) {
		t.Fatalf("language-version floor = %#v", versions)
	}
	if versions := goCompatibilityVersions("go1.26.0", "go1.26.6"); !reflect.DeepEqual(versions, []string{"go1.26.0"}) {
		t.Fatalf("same-minor floor = %#v", versions)
	}
	if versions := goCompatibilityVersions("go1.24.3", "go1.26.6"); !reflect.DeepEqual(versions, []string{"go1.24.3", "go1.25.0"}) {
		t.Fatalf("patch floor = %#v", versions)
	}
	if _, valid := goVersionParts("go1.26rc1"); valid {
		t.Fatal("release candidate produced stable compatibility parts")
	}
}

func TestRepositoryFromModules(t *testing.T) {
	modules := []RepositoryModule{
		{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
		{Directory: "differential", Path: "example.test/root/differential", GoVersion: "1.25.0", Toolchain: "go1.26.6", HasPackages: true},
		{Directory: "tools", Path: "example.test/root/tools", GoVersion: "1.26.0", Toolchain: "go1.26.6", Tools: []string{"example.test/check/cmd/check"}},
	}
	base := Repository{ID: "example", Self: "self", ExactGo: "wrong", LinterConfig: ".golangci.yml"}
	repository, err := RepositoryFromModules(modules, base)
	if err != nil {
		t.Fatal(err)
	}
	if repository.ExactGo != "go1.26.6" || !reflect.DeepEqual(repository.Modules, []Module{
		{Directory: "", Name: "Root", Packages: []string{"./..."}, Production: true},
		{Directory: "differential", Name: "differential", Packages: []string{"./..."}},
		{Directory: "tools", Name: "tools", Tools: []string{"example.test/check/cmd/check"}},
	}) || !reflect.DeepEqual(repository.TestScopes, []TestScope{
		{Name: "Root", Packages: []string{"./..."}},
		{Directory: "differential", Name: "differential", Packages: []string{"./..."}, SkipCoverage: true},
	}) || !reflect.DeepEqual(repository.FuzzModules, []FuzzModule{
		{Directory: ".", Path: "example.test/root"},
		{Directory: "differential", Path: "example.test/root/differential"},
	}) {
		t.Fatalf("repository = %#v", repository)
	}
	wantCompatibility := []Compatibility{
		{Version: "go1.24.0", Scopes: []string{"Root"}},
		{Version: "go1.25.0", Scopes: []string{"Root", "differential"}},
	}
	if !reflect.DeepEqual(repository.Compatibility, wantCompatibility) {
		t.Fatalf("compatibility = %#v", repository.Compatibility)
	}
}

func TestModuleDisplayNamePreservesUnicode(t *testing.T) {
	if got := moduleDisplayName("évidence/tools"); got != "évidence/tools" {
		t.Fatalf("name = %q", got)
	}
}

func TestRepositoryStaticControlsCoverDiscoveredModules(t *testing.T) {
	modules := []RepositoryModule{
		{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
		{Directory: "tools", Path: "example.test/root/tools", GoVersion: "1.26.0", Toolchain: "go1.26.6", Tools: []string{"example.test/check/cmd/check"}},
	}
	tool := Tool{Executable: "tool"}
	repository, err := RepositoryFromModules(modules, Repository{
		ID: "example", Self: "self", Go: tool, Linter: tool, Vulnerability: tool, LinterConfig: ".golangci.yml",
	})
	if err != nil {
		t.Fatal(err)
	}
	controls, err := repositoryStaticControls(repository)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]bool, len(controls))
	for _, control := range controls {
		identities[control.ID] = true
	}
	for _, identity := range []string{
		"module_00_tidy", "module_00_verify", "module_00_fix", "module_00_format",
		"module_00_vet", "module_00_lint", "module_00_vulnerabilities", "module_00_compile",
		"module_01_tidy", "module_01_verify", "module_01_vulnerabilities", "dependency_currency",
	} {
		if !identities[identity] {
			t.Fatalf("missing control %q in %#v", identity, controls)
		}
	}
}

func TestResolveRepositoryTool(t *testing.T) {
	root := t.TempDir()
	goExecutable := testExecutable(t)
	want := filepath.Join(root, "tool.exe")
	modules := []RepositoryModule{{
		Directory: "tools", Path: "example.test/root/tools", Tools: []string{"example.test/check/cmd/repository-check"},
	}}
	runner := func(_ context.Context, command proctree.Command) (proctree.Result, error) {
		if !reflect.DeepEqual(command.Arguments, []string{"-C", filepath.Join(root, "tools"), "tool", "-n", "repository-check"}) {
			t.Fatalf("arguments = %#v", command.Arguments)
		}
		if !slices.Contains(command.Environment, "GOFLAGS=-mod=readonly") {
			t.Fatalf("environment = %#v", command.Environment)
		}
		return proctree.Result{Started: true, ExitCode: 0, Outcome: proctree.OutcomeCompleted, Stdout: []byte(want + "\n")}, nil
	}
	tool := Tool{Executable: goExecutable, Timeout: verify.MaxTimeout, OutputLimit: MaxRepositoryCommandBytes}
	resolved, err := resolveRepositoryTool(t.Context(), root, modules, "example.test/check/cmd/repository-check", tool, runner)
	if err != nil || resolved != want {
		t.Fatalf("resolved = (%q, %v)", resolved, err)
	}
}

func TestDiscoverRepositoryRejectsToolReplacements(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.24.0\ntoolchain go1.26.6\n")
	writeDiscoveryFile(t, root, ".golangci.yml", "version: '2'\n")
	writeDiscoveryFile(t, root, "value.go", "package root\n")
	writeDiscoveryFile(t, root, "tools/go.mod", "module example.test/root/tools\n\ngo 1.24.0\ntoolchain go1.26.6\n\ntool example.test/check/cmd/check\n\nrequire example.test/check v0.0.0\nreplace example.test/check => ../testdata/check\n")
	if _, err := DiscoverRepository(t.Context(), root, discoveryGoTool(t)); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestResolveRepositoryToolRejectsAmbiguityAndMalformedOutput(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: verify.MaxTimeout, OutputLimit: MaxRepositoryCommandBytes}
	success := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, ExitCode: 0, Outcome: proctree.OutcomeCompleted, Stdout: []byte("relative\n")}, nil
	}
	for _, modules := range [][]RepositoryModule{
		nil,
		{{Directory: "tools", Tools: []string{"example.test/check/cmd/other"}}},
		{
			{Directory: "tools", Tools: []string{"example.test/check/cmd/check"}},
			{Directory: "workflow", Tools: []string{"example.test/check/cmd/check"}},
		},
	} {
		if _, err := resolveRepositoryTool(t.Context(), root, modules, "example.test/check/cmd/check", tool, success); !errors.Is(err, ErrRepositoryDiscovery) {
			t.Fatalf("error = %v", err)
		}
	}
	called := false
	escaping := []RepositoryModule{{Directory: "../outside", Tools: []string{"example.test/check/cmd/check"}}}
	if _, err := resolveRepositoryTool(t.Context(), root, escaping, "example.test/check/cmd/check", tool,
		func(context.Context, proctree.Command) (proctree.Result, error) {
			called = true
			return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: []byte(filepath.Join(root, "tool") + "\n")}, nil
		}); !errors.Is(err, ErrRepositoryDiscovery) || called {
		t.Fatalf("escaping resolver = (called %t, %v)", called, err)
	}
	modules := []RepositoryModule{{Directory: "tools", Tools: []string{"example.test/check/cmd/check"}}}
	if _, err := ResolveRepositoryTool(nilContext(), root, modules, "example.test/check/cmd/check", tool); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("public resolver error = %v", err)
	}
	if _, err := resolveRepositoryTool(t.Context(), "relative", modules, "example.test/check/cmd/check", tool, success); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("relative root error = %v", err)
	}
	if _, err := resolveRepositoryTool(t.Context(), root, modules, "example.test/check/cmd/check", tool, success); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("malformed output error = %v", err)
	}
	if _, err := resolveRepositoryTool(nilContext(), root, modules, "example.test/check/cmd/check", tool, success); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := resolveRepositoryTool(t.Context(), root, modules, "bad\nname", tool, success); !errors.Is(err, ErrRepositoryDiscovery) {
		t.Fatalf("invalid name error = %v", err)
	}
	failure := errors.New("run")
	failed := func(context.Context, proctree.Command) (proctree.Result, error) { return proctree.Result{}, failure }
	if _, err := resolveRepositoryTool(t.Context(), root, modules, "example.test/check/cmd/check", tool, failed); !errors.Is(err, failure) {
		t.Fatalf("run error = %v", err)
	}
}

func TestRepositoryFromModulesRejectsInvalidInputs(t *testing.T) {
	valid := []RepositoryModule{{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true}}
	excessTools := append([]RepositoryModule(nil), valid...)
	excessTools[0].Tools = make([]string, verify.MaxArguments+1)
	for _, test := range []struct {
		name    string
		modules []RepositoryModule
		base    Repository
	}{
		{name: "modules", modules: nil, base: Repository{ID: "example"}},
		{name: "invalid modules", modules: nil, base: Repository{ID: "example", Self: "self", LinterConfig: ".golangci.yml"}},
		{name: "repository", modules: valid},
		{name: "prepopulated", modules: valid, base: Repository{ID: "example", Modules: []Module{{Name: "Root"}}}},
		{name: "tool count", modules: excessTools, base: Repository{ID: "example", Self: "self", LinterConfig: ".golangci.yml"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RepositoryFromModules(test.modules, test.base); !errors.Is(err, verify.ErrInvalidPlan) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRepositoryFromModulesAcceptsToolsOnly(t *testing.T) {
	modules := []RepositoryModule{{Directory: ".", Path: "example.test/tools", GoVersion: "1.24.0", Toolchain: "go1.26.6", Tools: []string{"example.test/check/cmd/check"}}}
	repository, err := RepositoryFromModules(modules, Repository{ID: "example", Self: "self", LinterConfig: ".golangci.yml"})
	if err != nil || len(repository.TestScopes) != 0 || len(repository.FuzzModules) != 0 {
		t.Fatalf("tools-only repository = (%#v, %v)", repository, err)
	}
}
