package goverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

func TestRunFuzzCampaignUsesBoundedLanes(t *testing.T) {
	t.Parallel()
	campaign, targets := campaignFixture(t, 2)
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		if current == 2 {
			releaseOnce.Do(func() { close(release) })
		}
		<-release
		return successfulFuzzResult(), nil
	}
	var output bytes.Buffer
	if err := runFuzzCampaignWith(t.Context(), t.TempDir(), campaign, targets, &output, runner, "windows"); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 2 || active.Load() != 0 || output.String() != "example.test/module/FuzzFirst: 100 executions\nexample.test/module/pkg/FuzzSecond: 100 executions\n" {
		t.Fatalf("campaign = (maximum %d, active %d, output %q)", maximum.Load(), active.Load(), output.String())
	}
}

func TestRunFuzzCampaignCancelsAndJoinsLanes(t *testing.T) {
	t.Parallel()
	campaign, targets := campaignFixture(t, 2)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	var active atomic.Int32
	runner := func(ctx context.Context, command proctree.Command) (proctree.Result, error) {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		if len(started) == 2 {
			once.Do(func() { close(release) })
		}
		<-release
		if strings.Contains(command.Arguments[2], "FuzzFirst") {
			return proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure, Stdout: []byte("failed")}, proctree.ErrExit
		}
		<-ctx.Done()
		return proctree.Result{Started: true, ExitCode: -1, Outcome: proctree.OutcomeCancelled}, proctree.ErrCancelled
	}
	err := runFuzzCampaignWith(t.Context(), t.TempDir(), campaign, targets, io.Discard, runner, "windows")
	if !errors.Is(err, ErrFuzzCampaign) || !errors.Is(err, proctree.ErrExit) || active.Load() != 0 || !strings.Contains(err.Error(), "FuzzFirst") {
		t.Fatalf("campaign error = %v, active = %d", err, active.Load())
	}
}

func TestRunFuzzCampaignObservesCancellationAfterWorkersStart(t *testing.T) {
	campaign, targets := campaignFixture(t, 1)
	ctx, cancel := context.WithCancel(t.Context())
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		cancel()
		return successfulFuzzResult(), nil
	}
	if err := runFuzzCampaignWith(ctx, t.TempDir(), campaign, targets[:1], io.Discard, runner, "windows"); !errors.Is(err, context.Canceled) {
		t.Fatalf("campaign cancellation error = %v", err)
	}
}

func TestRunFuzzCampaignDoesNotRelabelCallerCancellation(t *testing.T) {
	campaign, targets := campaignFixture(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	var started atomic.Int32
	runner := func(runCtx context.Context, _ proctree.Command) (proctree.Result, error) {
		if started.Add(1) == 2 {
			cancel()
		}
		<-runCtx.Done()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCancelled}, errors.Join(proctree.ErrCancelled, runCtx.Err())
	}
	err := runFuzzCampaignWith(ctx, t.TempDir(), campaign, targets, io.Discard, runner, "windows")
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "FuzzFirst") || strings.Contains(err.Error(), "FuzzSecond") {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestRunFuzzCampaignRejectsInvalidBoundaries(t *testing.T) {
	t.Parallel()
	campaign, targets := campaignFixture(t, 1)
	root := t.TempDir()
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		return successfulFuzzResult(), nil
	}
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets, io.Discard, runner, "aix"); !errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("unsupported platform error = %v", err)
	}
	for _, test := range []struct {
		ctx    context.Context
		root   string
		output io.Writer
		run    fuzzRun
	}{
		{ctx: nil, root: root, output: io.Discard, run: runner},
		{ctx: t.Context(), root: "relative", output: io.Discard, run: runner},
		{ctx: t.Context(), root: root, output: nil, run: runner},
		{ctx: t.Context(), root: root, output: io.Discard, run: nil},
	} {
		if err := runFuzzCampaignWith(test.ctx, test.root, campaign, targets, test.output, test.run, "windows"); !errors.Is(err, ErrFuzzCampaign) {
			t.Fatalf("invalid campaign error = %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runFuzzCampaignWith(cancelled, root, campaign, targets, io.Discard, runner, "windows"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled campaign error = %v", err)
	}
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets, errorWriter{}, runner, "windows"); err == nil {
		t.Fatal("campaign accepted an output failure")
	}
	campaign.Jobs = MaxFuzzJobs + 1
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets, io.Discard, runner, "windows"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("invalid campaign repository error = %v", err)
	}
	campaign.Jobs = 0
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets[:1], io.Discard, runner, "windows"); err != nil {
		t.Fatalf("default lane campaign error = %v", err)
	}
	runner = func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Outcome: proctree.OutcomeExitFailure}, nil
	}
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets, io.Discard, runner, "windows"); !errors.Is(err, ErrFuzzCampaign) {
		t.Fatalf("non-completed campaign error = %v", err)
	}
	campaign.Go.Executable = "relative"
	called := false
	runner = func(context.Context, proctree.Command) (proctree.Result, error) {
		called = true
		return proctree.Result{Outcome: proctree.OutcomeCompleted}, nil
	}
	if err := runFuzzCampaignWith(t.Context(), root, campaign, targets, io.Discard, runner, "windows"); !errors.Is(err, verify.ErrInvalidPlan) || called {
		t.Fatalf("unadmitted campaign = (%v, called %t)", err, called)
	}
}

func TestRunFuzzCampaignValidatesBeforePlatformClassification(t *testing.T) {
	campaign, targets := campaignFixture(t, 1)
	campaign.Duration = "invalid"
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		return successfulFuzzResult(), nil
	}
	err := runFuzzCampaignWith(t.Context(), t.TempDir(), campaign, targets, io.Discard, runner, "aix")
	if !errors.Is(err, ErrFuzzInventory) || errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("invalid unsupported campaign error = %v", err)
	}
}

func TestRunFuzzCampaignRejectsInvalidTargets(t *testing.T) {
	campaign, _ := campaignFixture(t, 1)
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		return successfulFuzzResult(), nil
	}
	err := runFuzzCampaignWith(t.Context(), t.TempDir(), campaign, []FuzzTarget{{}}, io.Discard, runner, "windows")
	if !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("invalid target error = %v", err)
	}
}

func TestRunFuzzCampaignPublicOwner(t *testing.T) {
	t.Parallel()
	campaign, targets := campaignFixture(t, 1)
	campaign.Go.Executable = testExecutable(t)
	if err := RunFuzzCampaign(t.Context(), t.TempDir(), campaign, targets[:1], io.Discard); !errors.Is(err, ErrFuzzCampaign) {
		t.Fatalf("public campaign error = %v", err)
	}
}

func TestValidateFuzzControlsChecksEveryControl(t *testing.T) {
	executable := testExecutable(t)
	controls := make([]verify.Control, MaxFuzzTargets)
	for index := range controls {
		controls[index] = verify.Control{
			ID: fmt.Sprintf("fuzz_%04d", index), Name: "Fuzz Control",
			Command: verify.Command{Executable: executable, Timeout: time.Minute, OutputLimit: 1024},
		}
	}
	controls[len(controls)-1].Command.Executable = "relative"
	if err := validateFuzzControls(t.TempDir(), controls); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("later control error = %v", err)
	}
}

func TestDeterministicFuzzFailureSelection(t *testing.T) {
	t.Parallel()
	outcomes := []fuzzOutcome{{err: proctree.ErrCancelled}, {err: proctree.ErrExit}, {err: errors.New("later")}}
	if index, genuine := deterministicFuzzFailure(outcomes, 0); index != 1 || !genuine {
		t.Fatalf("failure = (%d, %t)", index, genuine)
	}
	outcomes[0].err = errors.New("first")
	if index, genuine := deterministicFuzzFailure(outcomes, 2); index != 0 || !genuine {
		t.Fatalf("first failure = (%d, %t)", index, genuine)
	}
	outcomes = []fuzzOutcome{{err: proctree.ErrCancelled}}
	if index, genuine := deterministicFuzzFailure(outcomes, 0); index != 0 || genuine {
		t.Fatalf("fallback = (%d, %t)", index, genuine)
	}
	outcomes = []fuzzOutcome{{}, {err: proctree.ErrCancelled}, {err: proctree.ErrCancelled}}
	if index, genuine := deterministicFuzzFailure(outcomes, 2); index != 1 || genuine {
		t.Fatalf("ordered cancellation = (%d, %t)", index, genuine)
	}
	if index, genuine := deterministicFuzzFailure([]fuzzOutcome{}, 2); index != 2 || genuine {
		t.Fatalf("empty fallback = (%d, %t)", index, genuine)
	}
}

func TestDeterministicFuzzFailureKeepsCleanup(t *testing.T) {
	outcomes := []fuzzOutcome{{
		result: proctree.Result{Outcome: proctree.OutcomeCleanupFailure},
		err:    errors.Join(proctree.ErrCancelled, context.Canceled, proctree.ErrCleanup),
	}}
	if index, genuine := deterministicFuzzFailure(outcomes, 0); index != 0 || !genuine {
		t.Fatalf("cleanup failure = (%d, %t)", index, genuine)
	}
}

func TestRunFuzzControlBoundsRetainedFailureOutput(t *testing.T) {
	t.Parallel()
	campaign, targets := campaignFixture(t, 1)
	control := fuzzControl(campaign, targets[0], 0)
	control.Command.Directory = "module"
	large := bytes.Repeat([]byte("x"), MaxFuzzDiagnosticBytes+1)
	outcome := runFuzzControl(t.Context(), t.TempDir(), control, 1, func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Stdout: large, Stderr: large, Outcome: proctree.OutcomeExitFailure}, proctree.ErrExit
	})
	if len(outcome.result.Stdout) != MaxFuzzDiagnosticBytes || len(outcome.result.Stderr) != MaxFuzzDiagnosticBytes {
		t.Fatalf("retained output = (%d, %d)", len(outcome.result.Stdout), len(outcome.result.Stderr))
	}
	if !bytes.Contains(outcome.result.Stdout, []byte("truncated")) || !bytes.HasSuffix(outcome.result.Stdout, large[len(large)-16:]) {
		t.Fatalf("retained output lost tail: %q", outcome.result.Stdout)
	}
	outcome = runFuzzControl(t.Context(), t.TempDir(), control, 1, func(context.Context, proctree.Command) (proctree.Result, error) {
		return successfulFuzzResult(), nil
	})
	if outcome.err != nil || outcome.result.Stdout != nil || outcome.result.Stderr != nil {
		t.Fatalf("successful outcome retained output = %#v", outcome)
	}
	outcome = runFuzzControl(t.Context(), t.TempDir(), control, 101, func(context.Context, proctree.Command) (proctree.Result, error) {
		return successfulFuzzResult(), nil
	})
	if !errors.Is(outcome.err, ErrFuzzCampaign) {
		t.Fatalf("incomplete execution outcome = %#v", outcome)
	}
	for _, invalid := range []proctree.Result{
		{ExitCode: 0, Outcome: proctree.OutcomeCompleted},
		{Started: true, ExitCode: 1, Outcome: proctree.OutcomeCompleted},
		{Started: true, ExitCode: 0, Outcome: proctree.OutcomeCompleted},
	} {
		outcome = runFuzzControl(t.Context(), t.TempDir(), control, 1, func(context.Context, proctree.Command) (proctree.Result, error) {
			return invalid, nil
		})
		if !errors.Is(outcome.err, ErrFuzzCampaign) {
			t.Fatalf("invalid successful outcome = %#v", outcome)
		}
	}
}

func TestRunFuzzCampaignAppliesAggregateTimeout(t *testing.T) {
	campaign, targets := campaignFixture(t, 1)
	campaign.Timeout = 10 * time.Millisecond
	runner := func(ctx context.Context, _ proctree.Command) (proctree.Result, error) {
		<-ctx.Done()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCancelled}, errors.Join(proctree.ErrCancelled, ctx.Err())
	}
	err := runFuzzCampaignWith(t.Context(), t.TempDir(), campaign, targets[:1], io.Discard, runner, "windows")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("aggregate timeout error = %v", err)
	}
}

func TestFuzzExecutionCount(t *testing.T) {
	for source, want := range map[string]bool{
		"fuzz: elapsed: 1s, execs: 1 (1/sec)\nPASS\nok  \texample.test/module\t1s":                                true,
		"fuzz: elapsed: 1s, execs: 1 (1/sec)\nPASS\nfixture teardown complete\nok  \texample.test/module\t1s":     true,
		"fuzz: elapsed: 1s, execs: 1 (1/sec), new interesting: 0 (total: 1)\nPASS\nok  \texample.test/module\t1s": true,
		"fuzz: elapsed: 1s, execs: 001 (1/sec)\nPASS\nok  \texample.test/module\t1s":                              false,
		"fuzz: elapsed: invalid, execs: 1 (1/sec)\nPASS\nok  \texample.test/module\t1s":                           false,
		"invalid\nPASS\nok  \texample.test/module\t1s":                                                            false,
		"fuzz: elapsed: 1s invalid\nPASS\nok  \texample.test/module\t1s":                                          false,
		"fuzz: elapsed: 1s, execs: 1\nPASS\nok  \texample.test/module\t1s":                                        false,
		"fuzz: elapsed: 1s, execs: 1 invalid\nPASS\nok  \texample.test/module\t1s":                                false,
		"fuzz: elapsed: 1s, execs: 1 (1/sec), invalid\nPASS\nok  \texample.test/module\t1s":                       false,
		"fuzz: elapsed: 1s, execs: 1 (invalid/sec)\nPASS\nok  \texample.test/module\t1s":                          false,
		"fuzz: elapsed: 1s, execs: 1 (/sec)\nPASS\nok  \texample.test/module\t1s":                                 false,
		"fuzz: elapsed: 1s, execs: 1 (01/sec)\nPASS\nok  \texample.test/module\t1s":                               false,
		"fuzz: elapsed: 1s, execs: 0 (0/sec)\nPASS\nok  \texample.test/module\t1s":                                false,
		"fuzz: gathering baseline": false,
		"execs: invalid":           false,
	} {
		_, got := terminalFuzzExecutions([]byte(source))
		if got != want {
			t.Fatalf("terminalFuzzExecutions(%q) = %t", source, got)
		}
	}
	if minimumFuzzExecutions(Campaign{Duration: "1s"}) != 1 || minimumFuzzExecutions(Campaign{Duration: "10x"}) != 10 {
		t.Fatal("minimum fuzz executions differ")
	}
	if minimumFuzzExecutions(Campaign{Duration: strings.Repeat("9", 100) + "x"}) != 0 {
		t.Fatal("overflowing fuzz executions accepted")
	}
	var output bytes.Buffer
	if err := writeFuzzOutcomes(t.Context(), []verify.Control{{Name: "Fuzz One"}}, []fuzzOutcome{{executions: 1}}, &output); err != nil || output.String() != "One: 1 execution\n" {
		t.Fatalf("single execution output = (%q, %v)", output.String(), err)
	}
}

func TestTerminalFuzzTestMainTeardown(t *testing.T) {
	root, err := filepath.Abs("testdata/fuzz-testmain")
	if err != nil {
		t.Fatal(err)
	}
	tool := discoveryGoTool(t)
	target := FuzzTarget{
		Module: "example.test/fuzz-testmain", Package: "example.test/fuzz-testmain", Name: "FuzzIdentity", Directory: ".", Argument: ".",
	}
	campaign := Campaign{Go: tool, Duration: "1x", Parallelism: 1, Jobs: 1}
	var output bytes.Buffer
	err = RunFuzzCampaign(t.Context(), root, campaign, []FuzzTarget{target}, &output)
	if !fuzzSupported(runtime.GOOS) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil || !strings.Contains(output.String(), "1 execution") {
		t.Fatalf("TestMain fuzz result = (%q, %v)", output.String(), err)
	}
}

func TestMaximumOutputWork(t *testing.T) {
	prefix := []byte("fuzz: elapsed: 1s, execs: 1 (1/sec)\nPASS\n")
	suffix := []byte("ok  \texample.test/module\t1s\n")
	output := make([]byte, 0, verify.MaxOutputBytes)
	output = append(output, prefix...)
	output = append(output, bytes.Repeat([]byte("x\n"), (verify.MaxOutputBytes-len(prefix)-len(suffix))/2)...)
	output = append(output, suffix...)
	if executions, valid := terminalFuzzExecutions(output); !valid || executions != 1 {
		t.Fatalf("maximum terminal result = (%d, %t)", executions, valid)
	}
	allocations := testing.AllocsPerRun(5, func() {
		_, _ = terminalFuzzExecutions(output)
	})
	if allocations > 1 {
		t.Fatalf("maximum terminal allocations = %.0f", allocations)
	}
	resultLine := []byte("BenchmarkValue-16\t1\t1 ns/op\n")
	benchmarkOutput := bytes.Repeat([]byte("noise\n"), (verify.MaxOutputBytes-len(resultLine))/len("noise\n"))
	benchmarkOutput = append(benchmarkOutput, resultLine...)
	targets := []BenchmarkTarget{{Name: "BenchmarkValue"}}
	if !containsBenchmarkResults(benchmarkOutput, targets) {
		t.Fatal("maximum benchmark result was rejected")
	}
	valid := false
	allocations = testing.AllocsPerRun(5, func() {
		valid = containsBenchmarkResults(benchmarkOutput, targets)
	})
	if !valid || allocations > 2 {
		t.Fatalf("maximum benchmark allocations = %.0f", allocations)
	}
}

func TestWriteFuzzOutcomesObservesCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writeFuzzOutcomes(cancelled, []verify.Control{{Name: "Fuzz One"}}, []fuzzOutcome{{executions: 1}}, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v", err)
	}
}

func successfulFuzzResult() proctree.Result {
	return proctree.Result{
		Started: true, Outcome: proctree.OutcomeCompleted,
		Stdout: []byte("fuzz: elapsed: 1s, execs: 100 (100/sec)\nPASS\nok  \texample.test/module\t1s\n"),
	}
}

func campaignFixture(t *testing.T, jobs int) (Campaign, []FuzzTarget) {
	t.Helper()
	executable := testExecutable(t)
	campaign := Campaign{
		Go:       Tool{Executable: executable, Timeout: time.Minute, OutputLimit: 1024},
		Duration: "10x", Parallelism: 1, Jobs: jobs,
	}
	targets := []FuzzTarget{
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzFirst", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module/pkg", Name: "FuzzSecond", Directory: ".", Argument: "./pkg"},
	}
	return campaign, targets
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }
