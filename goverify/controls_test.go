package goverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

func TestGoControlConstructors(t *testing.T) {
	t.Parallel()
	tool := Tool{Executable: "go", Environment: []string{"GOWORK=off"}, Timeout: time.Minute, OutputLimit: 1024}
	tests := []struct {
		name      string
		control   verify.Control
		arguments []string
		expected  []byte
		stderr    bool
	}{
		{name: "toolchain", control: Toolchain(tool, "", "go1.26.6"), arguments: []string{"env", "GOVERSION"}, expected: []byte("go1.26.6\n")},
		{name: "tidy", control: ModuleTidy(tool, "."), arguments: []string{"mod", "tidy", "-diff"}},
		{name: "verify", control: ModuleVerify(tool, "."), arguments: []string{"mod", "verify"}, expected: []byte("all modules verified\n"), stderr: true},
		{name: "fix", control: Fix(tool, ".", "./..."), arguments: []string{"fix", "-diff", "./..."}, expected: []byte{}, stderr: true},
		{name: "vet", control: Vet(tool, ".", "./..."), arguments: []string{"vet", "./..."}},
		{name: "test", control: Test(tool, ".", "./..."), arguments: []string{"test", "-count=1", "-shuffle=on", "./..."}},
		{name: "race", control: Race(tool, ".", "./..."), arguments: []string{"test", "-count=1", "-race", "-shuffle=on", "-vet=off", "./..."}},
		{name: "format", control: Format(tool, ".", "--config", ".golangci.yml"), arguments: []string{"fmt", "--diff", "--config", ".golangci.yml"}, expected: []byte{}, stderr: true},
		{name: "lint", control: Lint(tool, ".", "./..."), arguments: []string{"run", "./..."}},
		{name: "vulnerabilities", control: Vulnerabilities(tool, ".", "./..."), arguments: []string{"./..."}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := test.control.Command
			expectedDirectory := "."
			if test.name == "toolchain" {
				expectedDirectory = ""
			}
			if command.Executable != tool.Executable || command.Directory != expectedDirectory || !reflect.DeepEqual(command.Arguments, test.arguments) ||
				!reflect.DeepEqual(command.ExpectedStdout, test.expected) || (command.ExpectedStderr != nil) != test.stderr ||
				command.Timeout != tool.Timeout || command.OutputLimit != tool.OutputLimit {
				t.Fatalf("control = %#v", test.control)
			}
		})
	}
}

func TestControlOwnsArguments(t *testing.T) {
	arguments := []string{"./..."}
	control := Vulnerabilities(Tool{}, "", arguments...)
	arguments[0] = "changed"
	if !reflect.DeepEqual(control.Command.Arguments, []string{"./..."}) {
		t.Fatalf("arguments = %#v", control.Command.Arguments)
	}
}

func TestEvidenceControlsReportSuccessfulOutput(t *testing.T) {
	t.Parallel()
	tool := Tool{Executable: "go", Timeout: time.Minute, OutputLimit: 1024}
	benchmarks, err := benchmarkControls(tool, []BenchmarkTarget{{
		Module: "example.test/module", Package: "example.test/module", Name: "BenchmarkValue", Directory: ".", Argument: ".",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, control := range map[string]verify.Control{
		"race":      Race(tool, "", "./..."),
		"benchmark": benchmarks[0],
	} {
		if !control.Command.ShowSuccessOutput {
			t.Fatalf("%s does not report successful output", name)
		}
	}
	if Toolchain(tool, "", "go1.26.6").Command.ShowSuccessOutput || Lint(tool, "", "./...").Command.ShowSuccessOutput ||
		Vulnerabilities(tool, "", "./...").Command.ShowSuccessOutput {
		t.Fatal("routine controls report successful output")
	}
}

func TestFuzzControlConstruction(t *testing.T) {
	t.Parallel()
	campaign := Campaign{Go: Tool{Executable: "go", Timeout: time.Minute, OutputLimit: 1024}, Duration: "15s", Parallelism: 4}
	targets := []FuzzTarget{{Module: "example.test/module", Package: "example.test/module/pkg", Name: "FuzzDecode", Directory: ".", Argument: "./pkg"}}
	controls, err := fuzzControls(campaign, targets)
	if err != nil || len(controls) != 1 || controls[0].ID != "fuzz_0000" || controls[0].Name != "Fuzz example.test/module/pkg/FuzzDecode" ||
		controls[0].Command.Directory != "" ||
		!reflect.DeepEqual(controls[0].Command.Arguments, []string{"test", "-run=^$", "-fuzz=^FuzzDecode$", "-fuzztime=15s", "-parallel=4", "./pkg"}) {
		t.Fatalf("FuzzControls = (%#v, %v)", controls, err)
	}
	campaign.Duration = "1000000x"
	if controls, err = fuzzControls(campaign, targets); err != nil || len(controls) != 1 {
		t.Fatalf("execution campaign = (%#v, %v)", controls, err)
	}
	rootTarget := FuzzTarget{Module: "example.test/module", Package: "example.test/module", Name: "FuzzRoot", Directory: ".", Argument: "."}
	if controls, err = fuzzControls(campaign, []FuzzTarget{rootTarget}); err != nil || len(controls) != 1 {
		t.Fatalf("root campaign = (%#v, %v)", controls, err)
	}
}

func TestBenchmarkControlConstruction(t *testing.T) {
	tool := Tool{Executable: "go", Timeout: time.Minute, OutputLimit: 1024}
	targets := []BenchmarkTarget{
		{Module: "example.test/module", Package: "example.test/module/z", Name: "BenchmarkZulu", Directory: ".", Argument: "./z"},
		{Module: "example.test/module", Package: "example.test/module", Name: "BenchmarkRoot", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module/z", Name: "BenchmarkAlpha", Directory: ".", Argument: "./z"},
	}
	controls, err := benchmarkControls(tool, targets)
	if err != nil || len(controls) != 2 || controls[0].ID != "benchmark_000" || controls[1].Name != "Benchmark example.test/module/z" ||
		!reflect.DeepEqual(controls[1].Command.Arguments, []string{
			"test", "-run=^$", "-bench=^(?:BenchmarkAlpha|BenchmarkZulu)$", "-benchmem", "./z",
		}) {
		t.Fatalf("BenchmarkControls = (%#v, %v)", controls, err)
	}
}

func TestBenchmarkControlConstructionRejectsInvalidTargets(t *testing.T) {
	tool := Tool{}
	valid := BenchmarkTarget{Module: "module", Package: "module/pkg", Name: "BenchmarkValue", Directory: ".", Argument: "./pkg"}
	for _, targets := range [][]BenchmarkTarget{
		nil,
		{{}},
		{{Module: "module", Package: "module/pkg", Name: "benchmarkValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "other/pkg", Name: "BenchmarkValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "Benchmark" + strings.Repeat("V", MaxFuzzPathBytes), Directory: ".", Argument: "./pkg"}},
		{valid, valid},
		make([]BenchmarkTarget, MaxFuzzTargets+1),
	} {
		if _, err := benchmarkControls(tool, targets); !errors.Is(err, ErrBenchmarkInventory) {
			t.Fatalf("targets error = %v", err)
		}
	}
	wide := oversizedBenchmarkPatternTargets()
	if _, err := benchmarkControls(tool, wide); !errors.Is(err, ErrBenchmarkInventory) {
		t.Fatalf("wide pattern error = %v", err)
	}
	packages := make([]BenchmarkTarget, verify.MaxControls+1)
	for index := range packages {
		packageName := fmt.Sprintf("module/p%d", index)
		packages[index] = BenchmarkTarget{
			Module: "module", Package: packageName, Name: "BenchmarkValue", Directory: ".", Argument: "./" + strings.TrimPrefix(packageName, "module/"),
		}
	}
	if _, err := benchmarkControls(tool, packages); !errors.Is(err, ErrBenchmarkInventory) {
		t.Fatalf("package count error = %v", err)
	}
}

func oversizedBenchmarkPatternTargets() []BenchmarkTarget {
	valid := BenchmarkTarget{Module: "module", Package: "module/pkg", Directory: ".", Argument: "./pkg"}
	wide := make([]BenchmarkTarget, 17)
	for index := range wide {
		wide[index] = valid
		wide[index].Name = "Benchmark" + strings.Repeat("V", 4_000) + strconv.Itoa(index)
	}
	return wide
}

func TestBenchmarkResultAdmission(t *testing.T) {
	targets := []BenchmarkTarget{
		{Package: "example.test/module", Name: "BenchmarkOne"},
		{Package: "example.test/module", Name: "BenchmarkTwo"},
	}
	output := []byte("BenchmarkOne\t100\t10 ns/op\nBenchmarkTwo/sub-16\t100\t20 ns/op\t64 B/op\t1 allocs/op\n")
	if !containsBenchmarkResults(output, targets) {
		t.Fatal("complete benchmark results were rejected")
	}
	for _, invalid := range [][]byte{
		[]byte("BenchmarkOne-16\t100\t10 ns/op\n"),
		[]byte("--- SKIP: BenchmarkOne\n--- SKIP: BenchmarkTwo\n"),
		[]byte("BenchmarkOne\nBenchmarkTwo\n"),
		[]byte("BenchmarkOne-16\tinvalid\t10 ns/op\nBenchmarkTwo-16\t100\t20 ns/op\n"),
		[]byte("BenchmarkOne-16\t100\t10\nBenchmarkTwo-16\t100\t20 ns/op\n"),
		[]byte("BenchmarkOne-16\t100\tinvalid ns/op\nBenchmarkTwo-16\t100\t20 ns/op\n"),
		[]byte("BenchmarkOne-16\t100\t0x1p2 ns/op\nBenchmarkTwo-16\t100\t20 ns/op\n"),
		[]byte("BenchmarkOne-invalid\t100\t10 ns/op\nBenchmarkTwo-invalid\t100\t20 ns/op\n"),
	} {
		if containsBenchmarkResults(invalid, targets) {
			t.Fatalf("invalid benchmark results accepted: %q", invalid)
		}
	}
}

func TestBenchmarkResultGrammar(t *testing.T) {
	for _, value := range []string{"0", "-1", "0.0000003", "NaN", "+Inf", "-Inf"} {
		if !validBenchmarkNumber([]byte(value)) {
			t.Fatalf("valid benchmark number %q was rejected", value)
		}
	}
	for _, value := range []string{"-", ".1", "1.", "1.a", "0x1p2"} {
		if validBenchmarkNumber([]byte(value)) {
			t.Fatalf("invalid benchmark number %q was accepted", value)
		}
	}
	if !validBenchmarkUnit([]byte("unit\x7f")) {
		t.Fatal("valid control-byte benchmark unit was rejected")
	}
	for _, value := range []string{"", "ns op", "ns\top", "ns\u00a0op"} {
		if validBenchmarkUnit([]byte(value)) {
			t.Fatalf("invalid benchmark unit %q was accepted", value)
		}
	}
}

func TestRunBenchmarksRequiresDeclaredExecution(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/benchmark\n\ngo 1.21\n")
	writeDiscoveryFile(t, root, "value_test.go", "package benchmark\nimport \"testing\"\nfunc BenchmarkValue(b *testing.B) { for _, name := range []string{\"\", \"/case\", \"case/\", \"nested/slash\"} { b.Run(name, func(b *testing.B) {}) } }\nfunc BenchmarkOther(b *testing.B) {}\nfunc BenchmarkControlUnit(b *testing.B) { b.ReportMetric(1, \"unit\\x7f\") }\n")
	tool := discoveryGoTool(t)
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOTOOLCHAIN", "local")
	target := BenchmarkTarget{Module: "example.test/benchmark", Package: "example.test/benchmark", Name: "BenchmarkValue", Directory: ".", Argument: "."}
	other := target
	other.Name = "BenchmarkOther"
	controlUnit := target
	controlUnit.Name = "BenchmarkControlUnit"
	for _, processors := range []string{"1", "2"} {
		operationTool := tool
		operationTool.Environment = ReplaceEnvironment(operationTool.Environment, "GOMAXPROCS", processors)
		var output strings.Builder
		if err := RunBenchmarks(t.Context(), root, operationTool, []BenchmarkTarget{target, other, controlUnit}, &output); err != nil ||
			!strings.Contains(output.String(), "BenchmarkOther") || !strings.Contains(output.String(), "BenchmarkControlUnit") {
			t.Fatalf("%s-processor benchmark execution = (%q, %v)", processors, output.String(), err)
		}
		requireUnusualBenchmarkResults(t, []byte(output.String()), processors)
	}
	target.Name = "BenchmarkMissing"
	if err := RunBenchmarks(t.Context(), root, tool, []BenchmarkTarget{target}, io.Discard); !errors.Is(err, verify.ErrFailed) {
		t.Fatalf("missing benchmark error = %v", err)
	}
}

func requireUnusualBenchmarkResults(t *testing.T, output []byte, processors string) {
	t.Helper()
	suffix := ""
	if processors != "1" {
		suffix = "-" + processors
	}
	expected := map[string]bool{
		"BenchmarkValue/#00" + suffix:          false,
		"BenchmarkValue//case" + suffix:        false,
		"BenchmarkValue/case/" + suffix:        false,
		"BenchmarkValue/nested/slash" + suffix: false,
	}
	for line := range bytes.SplitSeq(output, []byte{'\n'}) {
		name, _ := benchmarkToken(line)
		if _, found := expected[string(name)]; !found {
			continue
		}
		identity, valid := benchmarkResult(line)
		if !valid || !bytes.Equal(identity, []byte("BenchmarkValue")) {
			t.Fatalf("benchmark result %q = (%q, %t)", line, identity, valid)
		}
		expected[string(name)] = true
	}
	for name, found := range expected {
		if !found {
			t.Fatalf("benchmark result %q was not emitted", name)
		}
	}
}

func TestRunBenchmarkBoundaries(t *testing.T) {
	target := BenchmarkTarget{Module: "example.test/module", Package: "example.test/module", Name: "BenchmarkValue", Directory: ".", Argument: "."}
	if err := RunBenchmarks(nilContext(), t.TempDir(), Tool{}, []BenchmarkTarget{target}, io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := RunBenchmarks(t.Context(), "relative", Tool{}, []BenchmarkTarget{target}, io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("relative root error = %v", err)
	}
	if err := RunBenchmarks(t.Context(), t.TempDir(), Tool{}, []BenchmarkTarget{target}, nil); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("nil output error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: 1024}
	if err := RunBenchmarks(t.Context(), t.TempDir(), tool, nil, io.Discard); !errors.Is(err, ErrBenchmarkInventory) {
		t.Fatalf("empty targets error = %v", err)
	}
	if err := RunBenchmarks(cancelled, t.TempDir(), tool, []BenchmarkTarget{target}, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if _, _, err := admitBenchmarkRun(t.TempDir(), Tool{}, []BenchmarkTarget{target}); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("invalid tool error = %v", err)
	}
	if _, _, err := admitBenchmarkRun(t.TempDir(), tool, oversizedBenchmarkPatternTargets()); !errors.Is(err, ErrBenchmarkInventory) {
		t.Fatalf("oversized pattern error = %v", err)
	}
}

func TestRunBenchmarkControlFailures(t *testing.T) {
	targets := []BenchmarkTarget{{Name: "BenchmarkValue"}}
	control := verify.Control{Command: verify.Command{OutputLimit: 1024, Timeout: time.Minute}}
	complete := proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted,
		Stdout: []byte("BenchmarkValue-16\t1\t1 ns/op\n"), Stderr: []byte("warning\n")}
	failed := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeExitFailure, Stdout: []byte("diagnostic\n")}, proctree.ErrExit
	}
	var diagnostic strings.Builder
	if err := runBenchmarkControlWith(t.Context(), t.TempDir(), control, targets, &diagnostic, failed); !errors.Is(err, verify.ErrFailed) || diagnostic.String() != "diagnostic\n" {
		t.Fatalf("run failure = (%q, %v)", diagnostic.String(), err)
	}
	missing := func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted,
			Stdout: []byte("BenchmarkOther-16\t1\t1 ns/op\n"), Stderr: []byte("missing target\n")}, nil
	}
	diagnostic.Reset()
	if err := runBenchmarkControlWith(t.Context(), t.TempDir(), control, targets, &diagnostic, missing); !errors.Is(err, verify.ErrFailed) ||
		diagnostic.String() != "BenchmarkOther-16\t1\t1 ns/op\nmissing target\n" {
		t.Fatalf("missing result = (%q, %v)", diagnostic.String(), err)
	}
	success := func(context.Context, proctree.Command) (proctree.Result, error) { return complete, nil }
	if err := runBenchmarkControlWith(t.Context(), t.TempDir(), control, targets, errorWriter{}, success); err == nil {
		t.Fatal("stdout writer failure was accepted")
	}
	if err := runBenchmarkControlWith(t.Context(), t.TempDir(), control, targets, &benchmarkFailureWriter{}, success); err == nil {
		t.Fatal("stderr writer failure was accepted")
	}
}

type benchmarkFailureWriter struct{ writes int }

func (writer *benchmarkFailureWriter) Write(value []byte) (int, error) {
	writer.writes++
	if writer.writes == 2 {
		return 0, errors.New("write")
	}
	return len(value), nil
}

func TestFuzzControlConstructionRejectsInvalidCampaigns(t *testing.T) {
	t.Parallel()
	valid := Campaign{Go: Tool{Timeout: time.Minute}, Duration: "15s", Parallelism: 1}
	target := FuzzTarget{Module: "module", Package: "module/pkg", Name: "FuzzValue", Directory: ".", Argument: "./pkg"}
	tests := []Campaign{
		{Go: valid.Go, Duration: valid.Duration, Parallelism: 0},
		{Go: valid.Go, Duration: valid.Duration, Parallelism: MaxFuzzParallelism + 1},
		{Go: valid.Go, Duration: "", Parallelism: 1},
		{Go: valid.Go, Duration: "invalid", Parallelism: 1},
		{Go: valid.Go, Duration: "x", Parallelism: 1},
		{Go: valid.Go, Duration: "01x", Parallelism: 1},
		{Go: valid.Go, Duration: "invalidx", Parallelism: 1},
		{Go: valid.Go, Duration: strings.Repeat("1", MaxFuzzWorkBytes+1) + "x", Parallelism: 1},
		{Go: valid.Go, Duration: time.Minute.String(), Parallelism: 1},
		{Go: valid.Go, Duration: "1000000001x", Parallelism: 1},
		{Go: valid.Go, Duration: valid.Duration, Parallelism: 1, Jobs: MaxFuzzJobs + 1},
		{Go: valid.Go, Duration: valid.Duration, Parallelism: 1, Timeout: -1},
		{Go: valid.Go, Duration: valid.Duration, Parallelism: 1, Timeout: verify.MaxTimeout + 1},
		{Go: Tool{}, Duration: "1x", Parallelism: 1},
		{Go: Tool{Timeout: -1}, Duration: "1x", Parallelism: 1},
		{Go: Tool{Timeout: verify.MaxTimeout + 1}, Duration: "1x", Parallelism: 1},
	}
	for _, campaign := range tests {
		if _, err := fuzzControls(campaign, []FuzzTarget{target}); !errors.Is(err, ErrFuzzInventory) {
			t.Fatalf("campaign %#v error = %v", campaign, err)
		}
	}
	invalidTargets := [][]FuzzTarget{
		nil,
		{{}},
		{{Module: "module", Package: "module/pkg", Name: "fuzzValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "Fuzz[", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "other/pkg", Name: "FuzzValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "FuzzValue", Directory: ".", Argument: "./other"}},
		{{Module: strings.Repeat("m", MaxFuzzPathBytes+1), Package: "module/pkg", Name: "FuzzValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/" + strings.Repeat("p", MaxFuzzPathBytes), Name: "FuzzValue", Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "Fuzz" + strings.Repeat("V", MaxFuzzPathBytes), Directory: ".", Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "FuzzValue", Directory: strings.Repeat("d", MaxFuzzPathBytes+1), Argument: "./pkg"}},
		{{Module: "module", Package: "module/pkg", Name: "FuzzValue", Directory: ".", Argument: "./" + strings.Repeat("p", MaxFuzzPathBytes)}},
		{target, target},
		make([]FuzzTarget, MaxFuzzTargets+1),
	}
	for _, targets := range invalidTargets {
		if _, err := fuzzControls(valid, targets); !errors.Is(err, ErrFuzzInventory) {
			t.Fatalf("targets error = %v", err)
		}
	}
}
