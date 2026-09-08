package goverify

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
)

func TestDiscoverFuzzTargets(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "z/z_test.go", `package z
import check "testing"
func FuzzZulu(f *check.F) {}
func Fuzzlower(f *check.F) {}
func FuzzWrong(a, b *check.F) {}
`)
	writeFuzzFile(t, root, "a_test.go", `package module
import (
    "fmt"
    . "testing"
)
func FuzzRoot(*F) {}
func Fuzz(*F) { fmt.Print() }
func FuzzValue(F) {}
`)
	writeFuzzFile(t, root, "ordinary.txt", "not Go source")
	writeFuzzFile(t, root, "ignored_test.go", `//go:build ignore
package module
import "testing"
func FuzzIgnored(*testing.F) {}
`)
	writeFuzzFile(t, root, "testdata/fixture_test.go", `package fixture
import "testing"
func FuzzFixture(*testing.F) {}
`)
	writeFuzzFile(t, root, "nested/go.mod", "module nested.test/module\n")
	writeFuzzFile(t, root, "nested/nested_test.go", `package nested
import "testing"
func FuzzNested(*testing.F) {}
`)
	targets, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), []FuzzModule{{Directory: ".", Path: "example.test/module"}})
	want := []FuzzTarget{
		{Module: "example.test/module", Package: "example.test/module", Name: "Fuzz", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzRoot", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module/z", Name: "FuzzZulu", Directory: ".", Argument: "./z"},
	}
	if err != nil || !reflect.DeepEqual(targets, want) {
		t.Fatalf("DiscoverFuzzTargets = (%#v, %v)", targets, err)
	}
}

func TestDiscoverTestTargetsIncludesBenchmarks(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "value_test.go", `package module
import check "testing"
func FuzzValue(*check.F) {}
func BenchmarkValue(*check.B) {}
func Benchmarklower(*check.B) {}
func BenchmarkWrong(*check.T) {}
`)
	targets, err := DiscoverTestTargets(t.Context(), root, discoveryGoTool(t), []FuzzModule{{Directory: ".", Path: "example.test/module"}})
	want := []BenchmarkTarget{
		{Module: "example.test/module", Package: "example.test/module", Name: "BenchmarkValue", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module", Name: "BenchmarkWrong", Directory: ".", Argument: "."},
	}
	if err != nil || len(targets.Fuzz) != 1 || !reflect.DeepEqual(targets.Benchmarks, want) {
		t.Fatalf("DiscoverTestTargets = (%#v, %v)", targets, err)
	}
}

func TestTargetDiscoveryUsesAdmittedGoContext(t *testing.T) {
	root := t.TempDir()
	architecture := "386"
	if runtime.GOARCH != "amd64" {
		architecture = "amd64"
	}
	writeFuzzFile(t, root, "ordinary_test.go", "package module\nimport \"testing\"\nfunc FuzzOrdinary(*testing.F) {}\n")
	for name, source := range map[string]string{
		"release_test.go": "//go:build go1.27\n\npackage module\nimport \"testing\"\nfunc FuzzRelease(*testing.F) {}\n",
		"cgo_test.go":     "//go:build cgo\n\npackage module\nimport \"testing\"\nfunc FuzzCgo(*testing.F) {}\n",
		"arch_test.go":    "//go:build " + architecture + "\n\npackage module\nimport \"testing\"\nfunc FuzzArchitecture(*testing.F) {}\n",
		"custom_test.go":  "//go:build custom\n\npackage module\nimport \"testing\"\nfunc FuzzCustom(*testing.F) {}\n",
	} {
		writeFuzzFile(t, root, name, source)
	}
	module := []FuzzModule{{Directory: ".", Path: "example.test/module"}}
	base := discoveryGoTool(t)
	base.Environment = ReplaceEnvironment(base.Environment, "CGO_ENABLED", "0")
	base.Environment = ReplaceEnvironment(base.Environment, "GOARCH", runtime.GOARCH)
	base.Environment = ReplaceEnvironment(base.Environment, "GOFLAGS", "")
	base.Environment = ReplaceEnvironment(base.Environment, "GOTOOLCHAIN", "go1.27.1")
	for _, test := range []struct {
		name   string
		mutate func(*Tool)
		want   []string
	}{
		{name: "older release", mutate: func(tool *Tool) {
			tool.Environment = ReplaceEnvironment(tool.Environment, "GOTOOLCHAIN", "go1.26.0")
		}, want: []string{"FuzzOrdinary"}},
		{name: "current release", mutate: func(*Tool) {}, want: []string{"FuzzOrdinary", "FuzzRelease"}},
		{name: "cgo", mutate: func(tool *Tool) {
			tool.Environment = ReplaceEnvironment(tool.Environment, "CGO_ENABLED", "1")
		}, want: []string{"FuzzCgo", "FuzzOrdinary", "FuzzRelease"}},
		{name: "architecture feature", mutate: func(tool *Tool) {
			tool.Environment = ReplaceEnvironment(tool.Environment, "GOARCH", architecture)
		}, want: []string{"FuzzArchitecture", "FuzzOrdinary", "FuzzRelease"}},
		{name: "custom tag", mutate: func(tool *Tool) {
			tool.Environment = ReplaceEnvironment(tool.Environment, "GOFLAGS", "-tags=custom")
		}, want: []string{"FuzzCustom", "FuzzOrdinary", "FuzzRelease"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tool := base
			test.mutate(&tool)
			targets, err := DiscoverFuzzTargets(t.Context(), root, tool, module)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, len(targets))
			for index, target := range targets {
				names[index] = target.Name
			}
			if !reflect.DeepEqual(names, test.want) {
				t.Fatalf("targets = %v", names)
			}
		})
	}
}

func TestCanonicalFuzzRootFailure(t *testing.T) {
	failure := errors.New("failure")
	if _, err := canonicalFuzzRootWith("root", func(string) (string, error) {
		return "", failure
	}); !errors.Is(err, ErrFuzzInventory) || !errors.Is(err, failure) {
		t.Fatalf("canonical root error = %v", err)
	}
}

func TestOpenFuzzRootFailure(t *testing.T) {
	failure := errors.New("failure")
	if _, err := openFuzzRootWith("root", func(string) (*os.Root, error) {
		return nil, failure
	}); !errors.Is(err, ErrFuzzInventory) || !errors.Is(err, failure) {
		t.Fatalf("open root error = %v", err)
	}
}

func TestTargetDiscoveryRejectsNonDirectoryRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(root, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := discoverTestTargetsWith(t.Context(), root, Tool{}, []FuzzModule{{Directory: ".", Path: "example.test/module"}}, proctree.Run)
	if !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("non-directory root error = %v", err)
	}
}

func TestTargetDiscoveryRetainsCompilerValidatedCandidates(t *testing.T) {
	source := []byte("package value\nimport (\n\t\"testing\"\n\tother \"example.test/types\"\n)\ntype FF = F\ntype F = (testing.F)\ntype B = testing.B\nfunc FuzzAlias(*(FF)) {}\nfunc FuzzEmptyResult(*F) () {}\nfunc FuzzWrong(*other.F) {}\nfunc BenchmarkAlias(*B) {}\nfunc BenchmarkWrong(*other.B) {}\n")
	fuzz, benchmarks, err := testTargetNames("value_test.go", source)
	if err != nil || !reflect.DeepEqual(fuzz, []string{"FuzzAlias", "FuzzEmptyResult", "FuzzWrong"}) ||
		!reflect.DeepEqual(benchmarks, []string{"BenchmarkAlias", "BenchmarkWrong"}) {
		t.Fatalf("targets = (%#v, %#v, %v)", fuzz, benchmarks, err)
	}
}

func TestBenchmarkTargetInventoryBoundaries(t *testing.T) {
	module := FuzzModule{Directory: ".", Path: "example.test/module"}
	owner := inventory{benchmarks: make([]BenchmarkTarget, MaxFuzzTargets), benchmarkIdentities: make(map[string]bool)}
	if err := owner.addBenchmark(module, "", "BenchmarkValue"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("benchmark bound error = %v", err)
	}
	owner = inventory{benchmarkIdentities: map[string]bool{"example.test/module/BenchmarkValue": true}}
	if err := owner.addBenchmark(module, "", "BenchmarkValue"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("duplicate benchmark error = %v", err)
	}
	if err := owner.collectFileTargets(module, "value_test.go", nil, []string{"BenchmarkValue"}); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("collected benchmark error = %v", err)
	}
	if !benchmarkName("Benchmark") || benchmarkName("Value") {
		t.Fatal("benchmark name boundary differs")
	}
}

func TestFuzzNamesAcceptsValidImportLiterals(t *testing.T) {
	for _, source := range []string{
		"package value\nimport check \"te\\x73ting\"\nfunc FuzzEscaped(*check.F) {}\n",
		"package value\nimport check `testing`\nfunc FuzzRaw(*check.F) {}\n",
	} {
		names, err := fuzzNames("value_test.go", []byte(source))
		if err != nil || len(names) != 1 {
			t.Fatalf("fuzzNames = (%q, %v)", names, err)
		}
	}
}

func TestDiscoverFuzzTargetsRejectsNilContext(t *testing.T) {
	if _, err := DiscoverFuzzTargets(nilContext(), t.TempDir(), Tool{}, []FuzzModule{{Directory: "."}}); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("DiscoverFuzzTargets error = %v", err)
	}
}

func TestDiscoverFuzzTargetsOrdersModulesAndNames(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "a/a_test.go", `package a
import "testing"
func FuzzZulu(*testing.F) {}
func FuzzAlpha(*testing.F) {}
`)
	writeFuzzFile(t, root, "nested/go.mod", "module alpha.test/module\n")
	writeFuzzFile(t, root, "nested/nested_test.go", `package nested
import "testing"
func FuzzNested(*testing.F) {}
`)
	modules := []FuzzModule{{Directory: ".", Path: "zulu.test/module"}, {Directory: "nested", Path: "alpha.test/module"}}
	targets, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), modules)
	if err != nil || len(targets) != 3 || targets[0].Module != "alpha.test/module" || targets[1].Name != "FuzzAlpha" || targets[2].Name != "FuzzZulu" {
		t.Fatalf("ordered targets = (%#v, %v)", targets, err)
	}
}

func TestDiscoverFuzzTargetsRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	valid := []FuzzModule{{Directory: ".", Path: "example.test/module"}}
	requests := []struct {
		root    string
		modules []FuzzModule
	}{
		{root: ".", modules: valid},
		{root: root, modules: nil},
		{root: root, modules: make([]FuzzModule, MaxFuzzModules+1)},
		{root: root, modules: []FuzzModule{{Directory: "../escape", Path: "module"}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: ""}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: string([]byte{0xff})}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: "invalid\x00module"}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: "invalid\nmodule"}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: "invalid\u202emodule"}}},
		{root: root, modules: []FuzzModule{{Directory: ".", Path: "module"}, {Directory: ".", Path: "other"}}},
	}
	if _, err := DiscoverFuzzTargets(t.Context(), filepath.Join(root, "missing"), discoveryGoTool(t), valid); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing root error = %v", err)
	}
	if _, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), []FuzzModule{{Directory: "missing", Path: "module"}}); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing module error = %v", err)
	}
	for _, request := range requests {
		if _, err := DiscoverFuzzTargets(t.Context(), request.root, discoveryGoTool(t), request.modules); !errors.Is(err, ErrFuzzInventory) {
			t.Fatalf("request %#v error = %v", request, err)
		}
	}
	writeFuzzFile(t, root, "broken_test.go", "package broken\nfunc (")
	if _, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), valid); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("broken source error = %v", err)
	}
}

func TestInventoryOwnerFailureBoundaries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFuzzFile(t, root, "tagged_test.go", "package tagged\nfunc (\n")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := opened.Close(); closeErr != nil {
			t.Errorf("close root: %v", closeErr)
		}
	})
	module := FuzzModule{Directory: ".", Path: "example.test/module"}
	owner := inventory{root: root, opened: opened, identities: make(map[string]bool)}
	checkInventoryEntryBoundaries(t, &owner, module)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err = owner.walkDirectory(cancelled, module, ".", "."); !errors.Is(err, context.Canceled) {
		t.Fatalf("walk cancellation = %v", err)
	}
	if err = owner.inspectFile(cancelled, module, ".", "tagged_test.go"); !errors.Is(err, context.Canceled) {
		t.Fatalf("inspect cancellation = %v", err)
	}
	owner.active = map[string]bool{"tagged_test.go": true}
	if err = owner.inspectFile(t.Context(), module, ".", "tagged_test.go"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("build constraint error = %v", err)
	}
	owner.targets = make([]FuzzTarget, MaxFuzzTargets)
	if err = owner.addTarget(module, "", "FuzzValue"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("target bound error = %v", err)
	}
	if _, err = owner.readSource("missing_test.go"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing source error = %v", err)
	}
	writeFuzzFile(t, root, "small_test.go", "package small")
	owner.bytes = MaxFuzzTotalBytes
	if _, err = owner.readSource("small_test.go"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("total source bound error = %v", err)
	}
}

func checkInventoryEntryBoundaries(t *testing.T, owner *inventory, module FuzzModule) {
	t.Helper()
	if err := owner.walkEntry(t.Context(), module, ".", ".", fixtureDirEntry{name: "linked", mode: fs.ModeSymlink}); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("symbolic link error = %v", err)
	}
	if containsGoModule([]os.DirEntry{fixtureDirEntry{name: "go.mod", mode: fs.ModeSymlink}}) {
		t.Fatal("symbolic link established a nested module boundary")
	}
	if err := owner.walkEntry(t.Context(), module, ".", ".", fixtureDirEntry{name: "pipe", mode: fs.ModeNamedPipe}); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("special file error = %v", err)
	}
	owner.entries = MaxFuzzEntries
	if _, err := owner.readDirectory(t.Context(), "."); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("entry bound error = %v", err)
	}
	owner.entries = MaxFuzzEntries + 1
	if _, err := owner.readDirectory(t.Context(), "."); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("exhausted entry bound error = %v", err)
	}
	owner.entries = 0
}

func TestReadSourceFileFailures(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	file, err := os.CreateTemp(root, "source-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("source"); err != nil {
		t.Fatal(err)
	}
	information, err := file.Stat()
	if closeErr := file.Close(); err != nil || closeErr != nil {
		t.Fatalf("fixture = (%v, %v)", err, closeErr)
	}
	readErr := errors.New("read")
	if _, err = readSourceFile(sourceFixture(information, errorReader{err: readErr}, nil, nil)); !errors.Is(err, readErr) {
		t.Fatalf("read error = %v", err)
	}
	closeErr := errors.New("close")
	if _, err = readSourceFile(sourceFixture(information, strings.NewReader("source"), nil, closeErr)); !errors.Is(err, closeErr) {
		t.Fatalf("close error = %v", err)
	}
	statErr := errors.New("stat")
	if _, err = readSourceFile(sourceFixture(nil, strings.NewReader(""), statErr, nil)); !errors.Is(err, statErr) {
		t.Fatalf("stat error = %v", err)
	}
	if _, err = readSourceFile(sourceFixture(nil, strings.NewReader(""), nil, nil)); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing information error = %v", err)
	}
	negative := sourceInformation{FileInfo: information, size: -1}
	if _, err = readSourceFile(sourceFixture(negative, strings.NewReader(""), nil, nil)); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("negative size error = %v", err)
	}
}

func TestFuzzHelpers(t *testing.T) {
	t.Parallel()
	if !fuzzName("Fuzz") || fuzzName("Value") {
		t.Fatal("fuzz name classification differs")
	}
	left := FuzzTarget{Module: "a", Package: "same", Name: "z"}
	right := FuzzTarget{Module: "b", Package: "same", Name: "a"}
	if compareTarget(left, right) >= 0 {
		t.Fatal("module comparison differs")
	}
	left.Module, right.Module = "same", "same"
	if compareTarget(left, right) <= 0 {
		t.Fatal("name comparison differs")
	}
}

func TestDiscoverFuzzTargetsRejectsDuplicatesAndOversize(t *testing.T) {
	root := t.TempDir()
	source := "package duplicate\nimport \"testing\"\nfunc FuzzSame(*testing.F) {}\n"
	writeFuzzFile(t, root, "a_test.go", source)
	writeFuzzFile(t, root, "b_test.go", source)
	modules := []FuzzModule{{Directory: ".", Path: "example.test/module"}}
	if _, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), modules); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("duplicate error = %v", err)
	}
	root = t.TempDir()
	writeFuzzFile(t, root, "large_test.go", "package value\n/*"+strings.Repeat("x", MaxFuzzSourceBytes)+"*/\n")
	if _, err := DiscoverFuzzTargets(t.Context(), root, discoveryGoTool(t), modules); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestDiscoverFuzzTargetsHonoursCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFuzzFile(t, root, "value_test.go", "package value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DiscoverFuzzTargets(ctx, root, discoveryGoTool(t), []FuzzModule{{Directory: ".", Path: "example.test/module"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestDiscoverTestTargetsObservesCancellationBeforeOrdering(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "value_test.go", "package value\n")
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	listed := []byte(`{"Dir":` + strconv.Quote(root) + `}`)
	run := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: listed}, nil
	}
	for failAt := 2; failAt <= 12; failAt++ {
		ctx := &stagedContext{Context: t.Context(), failAt: failAt}
		_, err = discoverTestTargetsWith(ctx, root, tool, []FuzzModule{{Directory: ".", Path: "example.test/module"}}, run)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("checkpoint %d error = %v", failAt, err)
		}
	}
}

func TestDiscoverTestTargetsRejectsUnresolvedListedFile(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	listed := []byte(`{"Dir":` + strconv.Quote(root) + `,"TestGoFiles":["missing_test.go"]}`)
	run := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: listed}, nil
	}
	_, err = discoverTestTargetsWith(t.Context(), root, tool, []FuzzModule{{Directory: ".", Path: "example.test/module"}}, run)
	if !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("unresolved file error = %v", err)
	}
}

func TestListedTestFileAdmissionBoundaries(t *testing.T) {
	root := t.TempDir()
	owner := inventory{root: root}
	module := FuzzModule{Directory: ".", Path: "example.test/module"}
	for _, listed := range []listedTestPackage{
		{Dir: "relative"},
		{Dir: filepath.Join(root, "..", "outside")},
		{Dir: root, TestGoFiles: []string{"../value_test.go"}},
		{Dir: root, XTestGoFiles: []string{"value.go"}},
		{Dir: root, TestGoFiles: []string{"value_test.go"}, XTestGoFiles: []string{"value_test.go"}},
	} {
		if err := owner.addListedTestFiles(make(map[string]bool), module, listed); !errors.Is(err, ErrFuzzInventory) {
			t.Fatalf("listed package %#v error = %v", listed, err)
		}
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := opened.Close(); closeErr != nil {
			t.Errorf("close root: %v", closeErr)
		}
	})
	owner.opened = opened
	owner.active = map[string]bool{"missing_test.go": true}
	owner.identities = make(map[string]bool)
	owner.benchmarkIdentities = make(map[string]bool)
	if err = owner.inspectFile(t.Context(), module, ".", "missing_test.go"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing active source error = %v", err)
	}
	if err = owner.walkDirectory(t.Context(), module, "missing", "missing"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing active directory error = %v", err)
	}
}

func TestChildGoInventoryFailures(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "ordinary.go", "package module\n")
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
	module := []FuzzModule{{Directory: ".", Path: "example.test/module"}}
	for _, output := range [][]byte{
		[]byte("{"),
		[]byte(`{"Dir":"relative","TestGoFiles":["value_test.go"]}`),
	} {
		run := func(context.Context, proctree.Command) (proctree.Result, error) {
			return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: output}, nil
		}
		if _, err := discoverTestTargetsWith(t.Context(), root, tool, module, run); !errors.Is(err, ErrFuzzInventory) {
			t.Fatalf("child inventory %q error = %v", output, err)
		}
	}
	missing := []byte(`{"Dir":` + strconv.Quote(root) + `,"TestGoFiles":["missing_test.go"]}`)
	run := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: missing}, nil
	}
	if _, err := discoverTestTargetsWith(t.Context(), root, tool, module, run); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("unconsumed child inventory error = %v", err)
	}
}

func FuzzSourceTargets(f *testing.F) {
	f.Add([]byte("package value\n"))
	f.Add([]byte("package value\nimport \"testing\"\nfunc FuzzValue(*testing.F) {}\n"))
	f.Add([]byte("package value\nimport \"testing\"\nfunc BenchmarkValue(*testing.B) {}\n"))
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxFuzzSourceBytes+1 {
			return
		}
		firstFuzz, firstBenchmarks, firstErr := testTargetNames("value_test.go", source)
		secondFuzz, secondBenchmarks, secondErr := testTargetNames("value_test.go", source)
		if !reflect.DeepEqual(firstFuzz, secondFuzz) || !reflect.DeepEqual(firstBenchmarks, secondBenchmarks) ||
			!sameErrorState(firstErr, secondErr) {
			t.Fatalf("inventory differs: (%#v, %#v, %v) and (%#v, %#v, %v)",
				firstFuzz, firstBenchmarks, firstErr, secondFuzz, secondBenchmarks, secondErr)
		}
		if firstErr == nil {
			for _, name := range firstFuzz {
				if !fuzzName(name) {
					t.Fatalf("invalid fuzz target = %q", name)
				}
			}
			for _, name := range firstBenchmarks {
				if !benchmarkName(name) {
					t.Fatalf("invalid benchmark = %q", name)
				}
			}
		}
	})
}

func writeFuzzFile(t *testing.T, root, name, source string) {
	t.Helper()
	module := filepath.Join(root, "go.mod")
	if _, err := os.Stat(module); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(module, []byte("module example.test/module\n\ngo 1.21\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sameErrorState(left, right error) bool {
	return (left == nil) == (right == nil) && errors.Is(left, ErrFuzzInventory) == errors.Is(right, ErrFuzzInventory)
}

type fixtureDirEntry struct {
	name string
	mode fs.FileMode
}

func (entry fixtureDirEntry) Name() string               { return entry.name }
func (entry fixtureDirEntry) IsDir() bool                { return entry.mode.IsDir() }
func (entry fixtureDirEntry) Type() fs.FileMode          { return entry.mode }
func (entry fixtureDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

func sourceFixture(information os.FileInfo, reader io.Reader, statErr, closeErr error) boundedSource {
	return boundedSource{
		reader: reader,
		stat:   func() (os.FileInfo, error) { return information, statErr },
		close:  func() error { return closeErr },
	}
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type sourceInformation struct {
	os.FileInfo
	size int64
}

func (information sourceInformation) Size() int64 { return information.size }
