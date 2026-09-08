package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/secengcommons/proctree"
	"github.com/secengcommons/verify/internal/exactwrite"
	"github.com/secengcommons/verify/internal/safeoutput"
)

const durationFractionScale = 100

// Execute admits a copied plan then runs the selected profile synchronously
func Execute(ctx context.Context, root string, plan Plan, profileID string, output io.Writer) (Result, error) {
	return execute(ctx, root, plan, profileID, output, proctree.Run, time.Now)
}

func execute(
	ctx context.Context,
	root string,
	plan Plan,
	profileID string,
	output io.Writer,
	runner func(context.Context, proctree.Command) (proctree.Result, error),
	clock func() time.Time,
) (Result, error) {
	started := clock()
	if ctx == nil || output == nil || !validIdentifier(profileID) {
		return Result{Plan: plan.ID, Profile: profileID, State: StateInvocationError, Duration: clock().Sub(started)}, ErrInvocation
	}
	if err := ctx.Err(); err != nil {
		return Result{Plan: plan.ID, Profile: profileID, State: StateCancelled, Duration: clock().Sub(started)}, errors.Join(ErrCancelled, err)
	}
	admitted, err := admitWithCancellation(root, plan, ctx.Err)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Result{Plan: plan.ID, Profile: profileID, State: StateCancelled, Duration: clock().Sub(started)},
				errors.Join(ErrCancelled, contextErr)
		}
		return Result{Plan: plan.ID, Profile: profileID, State: StateInvocationError, Duration: clock().Sub(started)}, err
	}
	profile, err := selectedProfile(admitted, profileID)
	if err != nil {
		return Result{Plan: admitted.id, Profile: profileID, State: StateInvocationError, Duration: clock().Sub(started)}, errors.Join(ErrInvocation, err)
	}
	result := Result{Plan: admitted.id, Profile: profile.ID, State: StatePass, Controls: make([]ControlResult, 0, len(profile.Controls))}
	if err = writeText(output, fmt.Sprintf("profile=%s controls=%d\n", profile.ID, len(profile.Controls))); err != nil {
		result.State = StateInvocationError
		result.Duration = clock().Sub(started)
		return result, errors.Join(ErrInvocation, ErrReporting, err)
	}
	err = executeControls(ctx, output, profile.Controls, &result, runner, clock)
	result.Duration = clock().Sub(started)
	if err != nil {
		return result, err
	}
	if err = writeText(output, fmt.Sprintf("\nPASS %s: %s in %s\n", profile.ID, controlCount(len(profile.Controls)), formatDuration(result.Duration))); err != nil {
		result.State = StateInvocationError
		return result, errors.Join(ErrInvocation, ErrReporting, err)
	}
	return result, nil
}

func executeControls(
	ctx context.Context,
	output io.Writer,
	controls []Control,
	result *Result,
	runner func(context.Context, proctree.Command) (proctree.Result, error),
	clock func() time.Time,
) error {
	for index, control := range controls {
		if err := ctx.Err(); err != nil {
			result.State = StateCancelled
			return errors.Join(ErrCancelled, err)
		}
		controlResult, controlErr := executeControl(ctx, output, control, index+1, len(controls), runner, clock)
		result.Controls = append(result.Controls, controlResult)
		if controlErr != nil {
			result.State = controlResult.State
			return controlErr
		}
	}
	if err := ctx.Err(); err != nil {
		result.State = StateCancelled
		return errors.Join(ErrCancelled, err)
	}
	return nil
}

func executeControl(
	parent context.Context,
	output io.Writer,
	control Control,
	position, total int,
	runner func(context.Context, proctree.Command) (proctree.Result, error),
	clock func() time.Time,
) (ControlResult, error) {
	started := clock()
	if err := writeText(output, fmt.Sprintf("\n[%d/%d] %s\n", position, total, control.Name)); err != nil {
		return ControlResult{ID: control.ID, State: StateInvocationError}, errors.Join(ErrInvocation, ErrReporting, err)
	}
	ctx, cancel := context.WithTimeout(parent, control.Command.Timeout)
	defer cancel()
	outcome, runErr := runner(ctx, proctree.Command{
		Executable: control.Command.Executable, Arguments: control.Command.Arguments, Directory: control.Command.Directory,
		Environment: control.Command.Environment, Input: control.Command.Input,
		StdoutLimit: control.Command.OutputLimit, StderrLimit: control.Command.OutputLimit,
	})
	duration := clock().Sub(started)
	state, resultErr := classifyOutcome(parent, ctx, outcome, runErr)
	if !matchesExpectedOutput(control.Command, outcome) {
		resultErr = errors.Join(ErrOutput, resultErr)
		if state == StatePass {
			state = StateFail
			resultErr = errors.Join(ErrFailed, resultErr)
		}
	}
	result := ControlResult{
		ID: control.ID, State: state, ExitCode: outcome.ExitCode,
		StdoutBytes: len(outcome.Stdout), StderrBytes: len(outcome.Stderr), Duration: duration,
	}
	if state != StatePass || control.Command.ShowSuccessOutput {
		if err := writeControlOutput(output, outcome); err != nil {
			result.State = StateInvocationError
			return result, errors.Join(ErrInvocation, ErrReporting, err, resultErr)
		}
	}
	if err := writeText(output, fmt.Sprintf("%s %s (%s)\n", stateLabel(state), control.Name, formatDuration(duration))); err != nil {
		result.State = StateInvocationError
		return result, errors.Join(ErrInvocation, ErrReporting, err, resultErr)
	}
	return result, resultErr
}

func formatDuration(value time.Duration) string {
	switch {
	case value < time.Microsecond:
		return fmt.Sprintf("%.2fns", float64(value)/float64(time.Nanosecond))
	case value < time.Millisecond:
		value = value.Round(time.Microsecond / durationFractionScale)
		if value >= time.Millisecond {
			return formatDuration(value)
		}
		return fmt.Sprintf("%.2fus", float64(value)/float64(time.Microsecond))
	case value < time.Second:
		value = value.Round(time.Millisecond / durationFractionScale)
		if value >= time.Second {
			return formatDuration(value)
		}
		return fmt.Sprintf("%.2fms", float64(value)/float64(time.Millisecond))
	case value < time.Minute:
		value = value.Round(time.Second / durationFractionScale)
		if value >= time.Minute {
			return formatDuration(value)
		}
		return fmt.Sprintf("%.2fs", float64(value)/float64(time.Second))
	default:
		value = value.Round(time.Second / durationFractionScale)
		minutes := value / time.Minute
		seconds := float64(value%time.Minute) / float64(time.Second)
		return fmt.Sprintf("%dm%05.2fs", minutes, seconds)
	}
}

func stateLabel(state State) string {
	switch state {
	case StatePass:
		return "PASS"
	case StateFail:
		return "FAIL"
	case StateCancelled:
		return "CANCELLED"
	case StateUnavailable:
		return "UNAVAILABLE"
	case StateInvocationError:
		return "INVOCATION ERROR"
	default:
		return "UNKNOWN"
	}
}

func controlCount(count int) string {
	if count == 1 {
		return "1 control"
	}
	return fmt.Sprintf("%d controls", count)
}

func matchesExpectedOutput(command Command, outcome proctree.Result) bool {
	return (command.ExpectedStdout == nil || bytes.Equal(command.ExpectedStdout, outcome.Stdout)) &&
		(command.ExpectedStderr == nil || bytes.Equal(command.ExpectedStderr, outcome.Stderr))
}

func classifyOutcome(parent, control context.Context, outcome proctree.Result, runErr error) (State, error) {
	switch {
	case errors.Is(runErr, proctree.ErrCleanup) || outcome.Outcome == proctree.OutcomeCleanupFailure:
		return StateFail, errors.Join(ErrFailed, proctree.ErrCleanup, runErr)
	case errors.Is(runErr, proctree.ErrUnsupported):
		return StateUnavailable, errors.Join(ErrUnavailable, runErr)
	case parent.Err() != nil:
		return StateCancelled, errors.Join(ErrCancelled, parent.Err(), runErr)
	case control.Err() != nil:
		return StateFail, errors.Join(ErrFailed, control.Err(), runErr)
	case !outcome.Started:
		return StateInvocationError, errors.Join(ErrInvocation, runErr)
	case runErr != nil || outcome.ExitCode != 0 || outcome.Outcome != proctree.OutcomeCompleted:
		return StateFail, errors.Join(ErrFailed, runErr)
	default:
		return StatePass, nil
	}
}

func writeControlOutput(output io.Writer, outcome proctree.Result) error {
	if err := writeOutputStream(output, outcome.Stdout); err != nil {
		return err
	}
	return writeOutputStream(output, outcome.Stderr)
}

func writeOutputStream(output io.Writer, value []byte) error {
	return safeoutput.Write(output, value)
}

func writeText(output io.Writer, value string) error { return exactwrite.Bytes(output, []byte(value)) }
