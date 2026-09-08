package verify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
)

func TestAdmitCopiesValidPlan(t *testing.T) {
	t.Parallel()
	root, plan := validPlan(t)
	admitted, err := admit(root, plan)
	if err != nil || admitted.id != plan.ID || len(admitted.profiles) != 1 {
		t.Fatalf("admit = (%#v, %v)", admitted, err)
	}
	plan.Profiles[0].Controls[0].Command.Arguments[0] = "changed"
	plan.Profiles[0].Controls[0].Command.Environment[0] = "VALUE=changed"
	plan.Profiles[0].Controls[0].Command.Input[0] = 'x'
	plan.Profiles[0].Controls[0].Command.ExpectedStdout = []byte("changed")
	command := admitted.profiles[0].Controls[0].Command
	if command.Arguments[0] == "changed" || command.Environment[0] == "VALUE=changed" || command.Input[0] == 'x' ||
		string(command.ExpectedStdout) == "changed" {
		t.Fatal("admitted plan retained caller-owned state")
	}
	if _, err := selectedProfile(admitted, "missing"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unknown profile error = %v", err)
	}
	subdirectory := filepath.Join(root, "subdirectory")
	if err := os.Mkdir(subdirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	plan.Profiles[0].Controls[0].Command.Directory = "subdirectory"
	if admitted, err = admit(root, plan); err != nil || admitted.profiles[0].Controls[0].Command.Directory != subdirectory {
		t.Fatalf("subdirectory admission = (%#v, %v)", admitted, err)
	}
}

func TestAdmitRetainsSuccessfulOutputSelection(t *testing.T) {
	t.Parallel()
	root, plan := validPlan(t)
	plan.Profiles[0].Controls[0].Command.ShowSuccessOutput = true
	admitted, err := admit(root, plan)
	if err != nil || !admitted.profiles[0].Controls[0].Command.ShowSuccessOutput {
		t.Fatalf("admit = (%#v, %v)", admitted, err)
	}
}

func TestExecuteRejectsNilContext(t *testing.T) {
	root, plan := validPlan(t)
	result, err := Execute(nilContext(), root, plan, "complete", io.Discard)
	if !errors.Is(err, ErrInvocation) || result.State != StateInvocationError || len(result.Controls) != 0 {
		t.Fatalf("Execute = (%#v, %v)", result, err)
	}
}

func TestExecuteRejectsPreCancelledContextBeforeAdmission(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	result, err := execute(cancelled, "invalid", Plan{}, "complete", io.Discard, func(context.Context, proctree.Command) (proctree.Result, error) {
		called = true
		return proctree.Result{}, nil
	}, time.Now)
	if !errors.Is(err, ErrCancelled) || result.State != StateCancelled || called {
		t.Fatalf("execute = (%#v, %v, called %t)", result, err, called)
	}
}

func TestExecuteObservesCancellationDuringAdmission(t *testing.T) {
	root, plan := validPlan(t)
	second := plan.Profiles[0].Controls[0]
	second.ID = "second"
	plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, second)
	ctx := &admissionContext{Context: t.Context(), cancelAt: 4}
	called := false
	result, err := execute(ctx, root, plan, "complete", io.Discard, func(context.Context, proctree.Command) (proctree.Result, error) {
		called = true
		return proctree.Result{}, nil
	}, time.Now)
	if !errors.Is(err, ErrCancelled) || result.State != StateCancelled || called {
		t.Fatalf("execute = (%#v, %v, called %t)", result, err, called)
	}
}

func TestAdmissionObservesCancellationBetweenProfiles(t *testing.T) {
	root, plan := validPlan(t)
	second := plan.Profiles[0]
	second.ID = "second"
	plan.Profiles = append(plan.Profiles, second)
	ctx := &admissionContext{Context: t.Context(), cancelAt: 3}
	if _, err := admitWithCancellation(root, plan, ctx.Err); !errors.Is(err, context.Canceled) {
		t.Fatalf("admission error = %v", err)
	}
}

type admissionContext struct {
	context.Context
	calls    int
	cancelAt int
}

func (ctx *admissionContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestPlanAggregateBounds(t *testing.T) {
	control := Control{Command: Command{Arguments: []string{"one"}, Environment: []string{"TWO=2"}, Input: []byte("input")}}
	plan := Plan{Profiles: []Profile{{Controls: []Control{control}}, {Controls: []Control{control}}}}
	if !validPlanAggregate(plan, 2, 26) {
		t.Fatal("exact aggregate bound was rejected")
	}
	if validPlanAggregate(plan, 1, 26) || validPlanAggregate(plan, 2, 25) || validPlanAggregate(plan, 0, 26) || validPlanAggregate(plan, 2, 0) ||
		validPlanAggregate(Plan{}, 2, 26) || validPlanAggregate(Plan{ID: "x", Profiles: []Profile{{ID: "x"}}}, 2, 1) {
		t.Fatal("invalid aggregate bound was accepted")
	}
	control.Command.Arguments = make([]string, MaxArguments+1)
	if validPlanAggregate(Plan{Profiles: []Profile{{Controls: []Control{control}}}}, 1, MaxPlanBytes) {
		t.Fatal("excess argument inventory was accepted")
	}
	control.Command.Arguments = nil
	control.Command.Environment = make([]string, MaxEnvironment+1)
	if validPlanAggregate(Plan{Profiles: []Profile{{Controls: []Control{control}}}}, 1, MaxPlanBytes) {
		t.Fatal("excess environment inventory was accepted")
	}
}

func TestValidateAcceptsValidPlan(t *testing.T) {
	t.Parallel()
	root, plan := validPlan(t)
	if err := Validate(root, plan); err != nil {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestBoundedEnvironmentAllocation(t *testing.T) {
	environment := []string{"PATH=value", "HOME=value", "TEMP=value", "SYSTEMROOT=value"}
	var operationErr error
	if allocations := testing.AllocsPerRun(100, func() {
		_, operationErr = boundedStrings(environment, true)
	}); allocations != 1 {
		t.Fatalf("bounded environment allocations = %f", allocations)
	}
	if operationErr != nil {
		t.Fatal(operationErr)
	}
}

func TestLexicalAdmissionBoundaries(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"a-b_2", "identifier"} {
		if !validIdentifier(value) {
			t.Fatalf("valid identifier rejected: %q", value)
		}
	}
	for _, value := range []string{"a.B", "a/B", "a B"} {
		if validIdentifier(value) {
			t.Fatalf("invalid identifier accepted: %q", value)
		}
	}
	for _, value := range []string{"", "INVALID-NAME"} {
		if validEnvironmentName(value) {
			t.Fatalf("invalid environment name accepted: %q", value)
		}
	}
}

func TestDispatchProcessOwner(t *testing.T) {
	if handled, code := DispatchProcessOwner([]string{"secverify"}); handled || code != 0 {
		t.Fatalf("dispatch = (%t, %d)", handled, code)
	}
}

type invalidPlanCase struct {
	name   string
	root   string
	mutate func(*Plan)
}

func TestAdmitRejectsInvalidPlanStructure(t *testing.T) {
	root, valid, _, file := invalidPlanFixture(t)
	cases := []invalidPlanCase{
		{name: "relative root", root: ".", mutate: noPlanChange},
		{name: "missing root", root: filepath.Join(root, "missing"), mutate: noPlanChange},
		{name: "file root", root: file, mutate: noPlanChange},
		{name: "plan identity", root: root, mutate: func(plan *Plan) { plan.ID = "INVALID" }},
		{name: "empty profiles", root: root, mutate: func(plan *Plan) { plan.Profiles = nil }},
		{name: "excess profiles", root: root, mutate: func(plan *Plan) {
			plan.Profiles = repeated(plan.Profiles[0], MaxProfiles+1, "profile_", func(value *Profile, id string) { value.ID = id })
		}},
		{name: "duplicate profile", root: root, mutate: func(plan *Plan) { plan.Profiles = append(plan.Profiles, plan.Profiles[0]) }},
		{name: "profile identity", root: root, mutate: func(plan *Plan) { plan.Profiles[0].ID = "" }},
		{name: "empty controls", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls = nil }},
		{name: "excess controls", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls = repeated(plan.Profiles[0].Controls[0], MaxControls+1, "control_", func(value *Control, id string) { value.ID = id })
		}},
		{name: "duplicate control", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, plan.Profiles[0].Controls[0])
		}},
		{name: "control identity", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].ID = "" }},
		{name: "control name", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Name = strings.Repeat("x", maxDisplayBytes+1) }},
		{name: "control name character", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Name = "invalid\x01" }},
		{name: "control name format", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Name = "invalid\u202e" }},
	}
	assertInvalidPlanCases(t, valid, cases)
}

func TestAdmitRejectsInvalidCommands(t *testing.T) {
	root, valid, subdirectory, _ := invalidPlanFixture(t)
	cases := invalidCommandCases(root, subdirectory)
	assertInvalidPlanCases(t, valid, cases)
}

func invalidPlanFixture(t *testing.T) (string, Plan, string, string) {
	t.Helper()
	root, valid := validPlan(t)
	subdirectory := filepath.Join(root, "subdirectory")
	if err := os.Mkdir(subdirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, valid, subdirectory, file
}

func invalidCommandCases(root, subdirectory string) []invalidPlanCase {
	return []invalidPlanCase{
		{name: "relative executable", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Executable = "tool" }},
		{name: "unclean executable", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.Executable = subdirectory + string(filepath.Separator) + ".." + string(filepath.Separator) + "tool"
		}},
		{name: "missing executable", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Executable = filepath.Join(root, "missing.exe") }},
		{name: "directory executable", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Executable = subdirectory }},
		{name: "zero timeout", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Timeout = 0 }},
		{name: "excess timeout", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Timeout = MaxTimeout + 1 }},
		{name: "zero output", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.OutputLimit = 0 }},
		{name: "excess output", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.OutputLimit = MaxOutputBytes + 1 }},
		{name: "excess arguments", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Arguments = make([]string, MaxArguments+1) }},
		{name: "argument bytes", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.Arguments = []string{strings.Repeat("x", MaxArgumentBytes+1)}
		}},
		{name: "argument zero", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Arguments = []string{"x\x00y"} }},
		{name: "excess environment", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Environment = make([]string, MaxEnvironment+1) }},
		{name: "environment bytes", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.Environment = []string{"VALUE=" + strings.Repeat("x", MaxEnvironmentBytes)}
		}},
		{name: "environment syntax", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Environment = []string{"INVALID"} }},
		{name: "environment duplicate", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Environment = []string{"VALUE=1", "value=2"} }},
		{name: "input bytes", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Input = make([]byte, MaxInputBytes+1) }},
		{name: "expected output bytes", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.ExpectedStdout = make([]byte, MaxExpectedBytes)
			plan.Profiles[0].Controls[0].Command.ExpectedStderr = []byte("x")
		}},
		{name: "expected stdout capture", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.OutputLimit = 1
			plan.Profiles[0].Controls[0].Command.ExpectedStdout = []byte("xx")
		}},
		{name: "expected stderr capture", root: root, mutate: func(plan *Plan) {
			plan.Profiles[0].Controls[0].Command.OutputLimit = 1
			plan.Profiles[0].Controls[0].Command.ExpectedStderr = []byte("xx")
		}},
		{name: "absolute directory", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Directory = subdirectory }},
		{name: "dot directory", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Directory = "." }},
		{name: "escaping directory", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Directory = "../escape" }},
		{name: "missing directory", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Directory = "missing" }},
		{name: "file directory", root: root, mutate: func(plan *Plan) { plan.Profiles[0].Controls[0].Command.Directory = "file" }},
	}
}

func assertInvalidPlanCases(t *testing.T, valid Plan, cases []invalidPlanCase) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := clonePlan(valid)
			test.mutate(&plan)
			if _, err := admit(test.root, plan); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("admit error = %v", err)
			}
		})
	}
}

func TestAdmissionHelpersRejectUnavailableRoots(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing", "tool")
	if _, err := canonicalExecutable(missing); err == nil {
		t.Fatal("executable beneath missing parent accepted")
	}
	missingRoot := filepath.Join(t.TempDir(), "missing")
	if _, err := admittedDirectoryCached(missingRoot, "child", map[string]string{"": missingRoot}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("directory error = %v", err)
	}
}

func TestCanonicalExecutableRejectsPostResolutionFailure(t *testing.T) {
	failure := errors.New("stat")
	_, err := canonicalExecutableWith("tool", func(string) (string, error) { return filepath.Join(t.TempDir(), "tool"), nil },
		func(string) (os.FileInfo, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatalf("canonical executable error = %v", err)
	}
}

func TestExecutePassesInOrderAndStopsOnFailure(t *testing.T) {
	root, plan := validPlan(t)
	second := plan.Profiles[0].Controls[0]
	second.ID, second.Name = "second", "Second"
	plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, second)
	order := make([]string, 0)
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		order = append(order, plan.Profiles[0].Controls[len(order)].ID)
		return proctree.Result{Started: true, Stdout: []byte("output\n"), Outcome: proctree.OutcomeCompleted}, nil
	}
	var output bytes.Buffer
	result, err := execute(t.Context(), root, plan, "complete", &output, runner, time.Now)
	if err != nil || result.State != StatePass || !reflect.DeepEqual(order, []string{"control", "second"}) || len(result.Controls) != 2 ||
		!strings.Contains(output.String(), "[1/2] First") || !strings.Contains(output.String(), "PASS complete: 2 controls") {
		t.Fatalf("Execute = (%#v, %v, %q, %#v)", result, err, output.String(), order)
	}
	order = nil
	runner = func(context.Context, proctree.Command) (proctree.Result, error) {
		order = append(order, "control")
		return proctree.Result{Started: true, ExitCode: 1, Stderr: []byte("failed\n")}, errors.New("exit")
	}
	result, err = execute(t.Context(), root, plan, "complete", &output, runner, time.Now)
	if !errors.Is(err, ErrFailed) || result.State != StateFail || len(order) != 1 || len(result.Controls) != 1 {
		t.Fatalf("failed Execute = (%#v, %v, %#v)", result, err, order)
	}
}

func TestExecuteWritesProgressAndProfileResult(t *testing.T) {
	root, plan := validPlan(t)
	second := plan.Profiles[0].Controls[0]
	second.ID, second.Name = "second", "Second"
	plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, second)
	clock := steppedClock(time.Unix(0, 0), 250*time.Millisecond)
	var output bytes.Buffer
	result, err := execute(t.Context(), root, plan, "complete", &output,
		fixedRunner(proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}), clock)
	if err != nil || result.State != StatePass {
		t.Fatalf("execute = (%#v, %v)", result, err)
	}
	want := "profile=complete controls=2\n\n[1/2] First\nPASS First (250.00ms)\n\n[2/2] Second\nPASS Second (250.00ms)\n\nPASS complete: 2 controls in 1.25s\n"
	if output.String() != want {
		t.Fatalf("output = %q", output.String())
	}
}

func TestExecuteReportsOnlySelectedSuccessfulOutput(t *testing.T) {
	root, plan := validPlan(t)
	selected := plan.Profiles[0].Controls[0]
	selected.ID, selected.Name = "selected", "Selected"
	selected.Command.ShowSuccessOutput = true
	plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, selected)
	outputs := [][]byte{[]byte("routine output\n"), []byte("retained evidence\n")}
	index := 0
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		result := proctree.Result{Started: true, Stdout: outputs[index], Outcome: proctree.OutcomeCompleted}
		index++
		return result, nil
	}
	var output bytes.Buffer
	result, err := execute(t.Context(), root, plan, "complete", &output, runner, time.Now)
	if err != nil || result.State != StatePass || strings.Contains(output.String(), "routine output") ||
		!strings.Contains(output.String(), "retained evidence") {
		t.Fatalf("execute = (%#v, %v, %q)", result, err, output.String())
	}

	output.Reset()
	runner = fixedRunner(proctree.Result{
		Started: true, ExitCode: 1, Stderr: []byte("failure evidence\n"), Outcome: proctree.OutcomeExitFailure,
	})
	result, err = execute(t.Context(), root, plan, "complete", &output, runner, time.Now)
	if !errors.Is(err, ErrFailed) || result.State != StateFail || !strings.Contains(output.String(), "failure evidence") {
		t.Fatalf("failed execute = (%#v, %v, %q)", result, err, output.String())
	}
}

func steppedClock(start time.Time, step time.Duration) func() time.Time {
	current := start.Add(-step)
	return func() time.Time {
		current = current.Add(step)
		return current
	}
}

func TestFormatDurationUsesTwoDecimalAdaptiveUnits(t *testing.T) {
	t.Parallel()
	for value, expected := range map[time.Duration]string{
		750 * time.Nanosecond:     "750.00ns",
		1250 * time.Nanosecond:    "1.25us",
		1250 * time.Microsecond:   "1.25ms",
		1250 * time.Millisecond:   "1.25s",
		2 * time.Minute:           "2m00.00s",
		999999 * time.Nanosecond:  "1.00ms",
		999999 * time.Microsecond: "1.00s",
		59999 * time.Millisecond:  "1m00.00s",
		119999 * time.Millisecond: "2m00.00s",
	} {
		if actual := formatDuration(value); actual != expected {
			t.Errorf("formatDuration(%s) = %q, want %q", value, actual, expected)
		}
	}
}

func TestStateLabels(t *testing.T) {
	t.Parallel()
	for state, want := range map[State]string{
		StatePass: "PASS", StateFail: "FAIL", StateCancelled: "CANCELLED", StateUnavailable: "UNAVAILABLE",
		StateInvocationError: "INVOCATION ERROR", State("unknown"): "UNKNOWN",
	} {
		if got := stateLabel(state); got != want {
			t.Fatalf("stateLabel(%q) = %q", state, got)
		}
	}
}

func TestExecuteClassifiesEveryState(t *testing.T) {
	root, plan := validPlan(t)
	tests := []struct {
		name    string
		outcome func(context.Context) (proctree.Result, error)
		state   State
		want    error
	}{
		{name: "unavailable", outcome: func(context.Context) (proctree.Result, error) { return proctree.Result{}, proctree.ErrUnsupported }, state: StateUnavailable, want: ErrUnavailable},
		{name: "invocation", outcome: func(context.Context) (proctree.Result, error) { return proctree.Result{}, errors.New("start") }, state: StateInvocationError, want: ErrInvocation},
		{name: "noncompleted", outcome: func(context.Context) (proctree.Result, error) {
			return proctree.Result{Started: true, Outcome: proctree.OutcomeCleanupFailure}, nil
		}, state: StateFail, want: ErrFailed},
		{name: "timeout", outcome: func(ctx context.Context) (proctree.Result, error) {
			<-ctx.Done()
			return proctree.Result{Started: true}, ctx.Err()
		}, state: StateFail, want: ErrFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePlan(plan)
			ctx := t.Context()
			if test.name == "timeout" {
				candidate.Profiles[0].Controls[0].Command.Timeout = time.Nanosecond
			}
			runner := func(ctx context.Context, _ proctree.Command) (proctree.Result, error) { return test.outcome(ctx) }
			result, err := execute(ctx, root, candidate, "complete", io.Discard, runner, time.Now)
			if !errors.Is(err, test.want) || result.State != test.state {
				t.Fatalf("Execute = (%#v, %v)", result, err)
			}
		})
	}
}

func TestExecuteClassifiesCancellationDuringControl(t *testing.T) {
	root, plan := validPlan(t)
	ctx, cancel := context.WithCancel(t.Context())
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		cancel()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCancelled}, errors.Join(proctree.ErrCancelled, context.Canceled)
	}
	result, err := execute(ctx, root, plan, "complete", io.Discard, runner, time.Now)
	if !errors.Is(err, ErrCancelled) || result.State != StateCancelled || len(result.Controls) != 1 {
		t.Fatalf("execute = (%#v, %v)", result, err)
	}
}

func TestExecuteKeepsCleanupFailureAboveCancellation(t *testing.T) {
	root, plan := validPlan(t)
	ctx, cancel := context.WithCancel(t.Context())
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		cancel()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCleanupFailure},
			errors.Join(proctree.ErrCancelled, context.Canceled, proctree.ErrUnsupported, proctree.ErrCleanup)
	}
	result, err := execute(ctx, root, plan, "complete", io.Discard, runner, time.Now)
	if !errors.Is(err, proctree.ErrCleanup) || errors.Is(err, ErrCancelled) || result.State != StateFail {
		t.Fatalf("cleanup result = (%#v, %v)", result, err)
	}
}

func TestExecuteStopsAfterCancellationBetweenControls(t *testing.T) {
	root, plan := validPlan(t)
	second := plan.Profiles[0].Controls[0]
	second.ID, second.Name = "second", "Second"
	plan.Profiles[0].Controls = append(plan.Profiles[0].Controls, second)
	ctx, cancel := context.WithCancel(t.Context())
	writer := &cancellingWriter{cancel: cancel, match: "PASS First"}
	runs := 0
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		runs++
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, nil
	}
	result, err := execute(ctx, root, plan, "complete", writer, runner, time.Now)
	if !errors.Is(err, ErrCancelled) || result.State != StateCancelled || runs != 1 || len(result.Controls) != 1 {
		t.Fatalf("execute = (%#v, %v, runs %d)", result, err, runs)
	}
}

func TestExecuteChecksCancellationBeforeFinalAcknowledgement(t *testing.T) {
	root, plan := validPlan(t)
	ctx, cancel := context.WithCancel(t.Context())
	writer := &cancellingWriter{cancel: cancel, match: "PASS First"}
	result, err := execute(ctx, root, plan, "complete", writer,
		fixedRunner(proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}), time.Now)
	if !errors.Is(err, ErrCancelled) || result.State != StateCancelled || len(result.Controls) != 1 {
		t.Fatalf("pre-acknowledgement cancellation = (%#v, %v)", result, err)
	}

	ctx, cancel = context.WithCancel(t.Context())
	writer = &cancellingWriter{cancel: cancel, match: "PASS complete:"}
	result, err = execute(ctx, root, plan, "complete", writer,
		fixedRunner(proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}), time.Now)
	if err != nil || result.State != StatePass || ctx.Err() == nil {
		t.Fatalf("acknowledgement cancellation = (%#v, %v, %v)", result, err, ctx.Err())
	}
}

func TestExecuteRejectsInvocationAndWriterFailures(t *testing.T) {
	root, plan := validPlan(t)
	if result, err := Execute(t.Context(), root, Plan{}, "complete", io.Discard); !errors.Is(err, ErrInvalidPlan) || result.State != StateInvocationError {
		t.Fatalf("invalid plan = (%#v, %v)", result, err)
	}
	if result, err := Execute(t.Context(), root, plan, "missing", io.Discard); !errors.Is(err, ErrInvocation) || result.State != StateInvocationError {
		t.Fatalf("unknown profile = (%#v, %v)", result, err)
	}
	if result, err := Execute(t.Context(), root, plan, strings.Repeat("x", maxIdentifierBytes+1), io.Discard); !errors.Is(err, ErrInvocation) || result.State != StateInvocationError {
		t.Fatalf("invalid profile = (%#v, %v)", result, err)
	}
	if result, err := Execute(t.Context(), root, plan, "complete", nil); !errors.Is(err, ErrInvocation) || result.State != StateInvocationError {
		t.Fatalf("nil writer = (%#v, %v)", result, err)
	}
	checkExecuteWriterFailures(t, root, plan)
}

func checkExecuteWriterFailures(t *testing.T, root string, plan Plan) {
	t.Helper()
	plan.Profiles[0].Controls[0].Command.ShowSuccessOutput = true
	runner := fixedRunner(proctree.Result{Started: true, Stdout: []byte("value"), Outcome: proctree.OutcomeCompleted})
	for name, writer := range map[string]io.Writer{"zero": zeroWriter{}, "error": errorWriter{}, "invalid": invalidWriter{}} {
		t.Run(name, func(t *testing.T) {
			result, err := execute(t.Context(), root, plan, "complete", writer, runner, time.Now)
			if !errors.Is(err, ErrInvocation) || result.State != StateInvocationError {
				t.Fatalf("Execute = (%#v, %v)", result, err)
			}
		})
	}
	runner = fixedRunner(proctree.Result{Started: true, Stdout: []byte("stdout"), Stderr: []byte("stderr"), Outcome: proctree.OutcomeCompleted})
	for _, failureCall := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		result, err := execute(t.Context(), root, plan, "complete", &stagedWriter{failureCall: failureCall}, runner, time.Now)
		if !errors.Is(err, ErrInvocation) || result.State != StateInvocationError {
			t.Fatalf("write failure %d = (%#v, %v)", failureCall, result, err)
		}
	}
}

func TestWriteControlOutputSeparatesStreams(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := writeControlOutput(&output, proctree.Result{Stdout: []byte("stdout"), Stderr: []byte("stderr")}); err != nil ||
		output.String() != "stdout\nstderr\n" {
		t.Fatalf("output = (%q, %v)", output.String(), err)
	}
}

func TestWriteControlOutputEscapesTerminalAndWorkflowCommands(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	result := proctree.Result{
		Stdout: []byte("::warning::value\nsafe\tvalue\n"),
		Stderr: []byte{'\x1b', '[', '2', 'J', 0xff, '\r', '\n'},
	}
	want := "\\x3a:warning::value\nsafe\tvalue\n\\x1b[2J\\xff\\x0d\n"
	if err := writeControlOutput(&output, result); err != nil || output.String() != want {
		t.Fatalf("safe output = (%q, %v)", output.String(), err)
	}
}

func TestExecuteRequiresExpectedOutput(t *testing.T) {
	root, plan := validPlan(t)
	command := &plan.Profiles[0].Controls[0].Command
	command.ExpectedStdout = []byte("expected")
	command.ExpectedStderr = []byte{}
	runner := fixedRunner(proctree.Result{Started: true, Stdout: []byte("actual"), Outcome: proctree.OutcomeCompleted})
	result, err := execute(t.Context(), root, plan, "complete", io.Discard, runner, time.Now)
	if !errors.Is(err, ErrOutput) || result.State != StateFail {
		t.Fatalf("mismatch = (%#v, %v)", result, err)
	}
	runner = fixedRunner(proctree.Result{Started: true, Stdout: []byte("expected"), Outcome: proctree.OutcomeCompleted})
	result, err = execute(t.Context(), root, plan, "complete", io.Discard, runner, time.Now)
	if err != nil || result.State != StatePass {
		t.Fatalf("match = (%#v, %v)", result, err)
	}
}

func TestOutputMismatchPreservesLifecycleState(t *testing.T) {
	root, plan := validPlan(t)
	plan.Profiles[0].Controls[0].Command.ExpectedStdout = []byte("expected")
	tests := []struct {
		name    string
		ctx     context.Context
		outcome proctree.Result
		err     error
		state   State
		want    error
	}{
		{name: "unavailable", ctx: t.Context(), outcome: proctree.Result{Outcome: proctree.OutcomeUnsupported}, err: proctree.ErrUnsupported, state: StateUnavailable, want: ErrUnavailable},
		{name: "invocation", ctx: t.Context(), outcome: proctree.Result{Outcome: proctree.OutcomeStartFailure}, err: proctree.ErrStart, state: StateInvocationError, want: ErrInvocation},
		{name: "exit", ctx: t.Context(), outcome: proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure}, err: proctree.ErrExit, state: StateFail, want: ErrFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := func(context.Context, proctree.Command) (proctree.Result, error) { return test.outcome, test.err }
			result, err := execute(test.ctx, root, plan, "complete", io.Discard, runner, time.Now)
			if !errors.Is(err, ErrOutput) || !errors.Is(err, test.want) || result.State != test.state {
				t.Fatalf("mismatch = (%#v, %v)", result, err)
			}
		})
	}
}

func validPlan(t testing.TB) (string, Plan) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return root, Plan{ID: "plan", Profiles: []Profile{{
		ID: "complete", Controls: []Control{{
			ID: "control", Name: "First", Command: Command{
				Executable: executable, Arguments: []string{"argument"}, Environment: []string{"VALUE=one"}, Input: []byte("input"),
				Timeout: time.Second, OutputLimit: 1024,
			},
		}},
	}}}
}

func clonePlan(value Plan) Plan {
	result := value
	result.Profiles = append([]Profile(nil), value.Profiles...)
	for profileIndex := range result.Profiles {
		result.Profiles[profileIndex].Controls = append([]Control(nil), value.Profiles[profileIndex].Controls...)
		for controlIndex := range result.Profiles[profileIndex].Controls {
			command := &result.Profiles[profileIndex].Controls[controlIndex].Command
			command.Arguments = append([]string(nil), command.Arguments...)
			command.Environment = append([]string(nil), command.Environment...)
			command.Input = append([]byte(nil), command.Input...)
			command.ExpectedStdout = cloneBytes(command.ExpectedStdout)
			command.ExpectedStderr = cloneBytes(command.ExpectedStderr)
		}
	}
	return result
}

func repeated[T any](value T, count int, prefix string, setID func(*T, string)) []T {
	result := make([]T, count)
	for index := range result {
		result[index] = value
		setID(&result[index], prefix+strconv.Itoa(index))
	}
	return result
}

func noPlanChange(*Plan) {}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failure") }

type invalidWriter struct{}

func (invalidWriter) Write(value []byte) (int, error) { return len(value) + 1, nil }

type stagedWriter struct {
	calls       int
	failureCall int
}

type cancellingWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
	match  string
}

func (writer *cancellingWriter) Write(value []byte) (int, error) {
	written, err := writer.Buffer.Write(value)
	if strings.Contains(writer.String(), writer.match) {
		writer.cancel()
	}
	return written, err
}

func (writer *stagedWriter) Write(value []byte) (int, error) {
	writer.calls++
	if writer.calls == writer.failureCall {
		return 0, errors.New("staged write failure")
	}
	return len(value), nil
}

func fixedRunner(result proctree.Result) func(context.Context, proctree.Command) (proctree.Result, error) {
	return func(context.Context, proctree.Command) (proctree.Result, error) { return result, nil }
}

func nilContext() context.Context { return nil }
