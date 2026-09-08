package goverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/exactwrite"
)

var ErrFuzzCampaign = errors.New("go fuzz campaign failed")

const decimalBase = 10
const unsignedIntegerBits = 64

// RunFuzzCampaign executes every exact target under one aggregate owner
func RunFuzzCampaign(ctx context.Context, root string, campaign Campaign, targets []FuzzTarget, output io.Writer) error {
	return runFuzzCampaignWith(ctx, root, campaign, targets, output, proctree.Run, runtime.GOOS)
}

type fuzzRun func(context.Context, proctree.Command) (proctree.Result, error)

type fuzzOutcome struct {
	result     proctree.Result
	err        error
	executions uint64
}

func runFuzzCampaignWith(ctx context.Context, root string, campaign Campaign, targets []FuzzTarget, output io.Writer, run fuzzRun, goos string) error {
	if ctx == nil || !filepath.IsAbs(root) || output == nil || run == nil {
		return ErrFuzzCampaign
	}
	if err := validCampaignOwner(campaign); err != nil {
		return errors.Join(ErrFuzzCampaign, err)
	}
	if !fuzzSupported(goos) {
		return errors.Join(ErrFuzzCampaign, verify.ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrFuzzCampaign, err)
	}
	controls, err := fuzzControls(campaign, targets)
	if err != nil {
		return errors.Join(ErrFuzzCampaign, err)
	}
	if err = validateFuzzControls(root, controls); err != nil {
		return errors.Join(ErrFuzzCampaign, err)
	}
	ctx, cancel := context.WithTimeout(ctx, campaignDeadline(campaign, len(targets)))
	defer cancel()
	jobs := campaign.Jobs
	if jobs == 0 {
		jobs = 1
	}
	return executeFuzzControls(ctx, root, controls, jobs, minimumFuzzExecutions(campaign), output, run)
}

func validateFuzzControls(root string, controls []verify.Control) error {
	profile := verify.Profile{ID: "fuzz_campaign", Controls: controls}
	return verify.Validate(root, verify.Plan{ID: "fuzz_campaign", Profiles: []verify.Profile{profile}})
}

func executeFuzzControls(ctx context.Context, root string, controls []verify.Control, jobs int, minimum uint64, output io.Writer, run fuzzRun) error {
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	outcomes := make([]fuzzOutcome, len(controls))
	var next atomic.Int64
	var first sync.Once
	var failed atomic.Bool
	var firstIndex int
	forWorker := func() {
		for {
			if ctx.Err() != nil {
				return
			}
			index := int(next.Add(1) - 1)
			if index >= len(controls) {
				return
			}
			outcomes[index] = runFuzzControl(ctx, root, controls[index], minimum, run)
			if outcomes[index].err != nil {
				first.Do(func() {
					failed.Store(true)
					firstIndex = index
					cancel()
				})
			}
		}
	}
	var workers sync.WaitGroup
	workers.Add(min(jobs, len(controls)))
	for range min(jobs, len(controls)) {
		go func() {
			defer workers.Done()
			forWorker()
		}()
	}
	workers.Wait()
	if failed.Load() {
		failureIndex, genuine := deterministicFuzzFailure(outcomes, firstIndex)
		if !genuine {
			if err := parent.Err(); err != nil {
				return errors.Join(ErrFuzzCampaign, err)
			}
		}
		return fuzzCampaignError(controls[failureIndex], outcomes[failureIndex])
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrFuzzCampaign, err)
	}
	return writeFuzzOutcomes(ctx, controls, outcomes, output)
}

func deterministicFuzzFailure(outcomes []fuzzOutcome, fallback int) (int, bool) {
	for index, outcome := range outcomes {
		if outcome.err != nil && (errors.Is(outcome.err, proctree.ErrCleanup) || outcome.result.Outcome == proctree.OutcomeCleanupFailure) {
			return index, true
		}
	}
	for index, outcome := range outcomes {
		if outcome.err != nil && !errors.Is(outcome.err, proctree.ErrCancelled) && !errors.Is(outcome.err, context.Canceled) {
			return index, true
		}
	}
	for index, outcome := range outcomes {
		if outcome.err != nil {
			return index, false
		}
	}
	return fallback, false
}

func writeFuzzOutcomes(ctx context.Context, controls []verify.Control, outcomes []fuzzOutcome, output io.Writer) error {
	for index, control := range controls {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrFuzzCampaign, err)
		}
		name := strings.TrimPrefix(control.Name, "Fuzz ")
		line := fmt.Sprintf("%s: %d executions\n", name, outcomes[index].executions)
		if outcomes[index].executions == 1 {
			line = name + ": 1 execution\n"
		}
		if err := exactwrite.Bytes(output, []byte(line)); err != nil {
			return errors.Join(ErrFuzzCampaign, err)
		}
	}
	return nil
}

func runFuzzControl(ctx context.Context, root string, control verify.Control, minimum uint64, run fuzzRun) fuzzOutcome {
	directory := root
	if control.Command.Directory != "" {
		directory = filepath.Join(root, filepath.FromSlash(control.Command.Directory))
	}
	result, err := run(ctx, proctree.Command{
		Executable: control.Command.Executable, Arguments: control.Command.Arguments, Directory: directory,
		Environment: control.Command.Environment, Input: control.Command.Input,
		StdoutLimit: control.Command.OutputLimit, StderrLimit: control.Command.OutputLimit, Timeout: control.Command.Timeout,
	})
	if err == nil && (!result.Started || result.ExitCode != 0 || result.Outcome != proctree.OutcomeCompleted) {
		err = ErrFuzzCampaign
	}
	executions := uint64(0)
	completed := false
	if err == nil {
		executions, completed = terminalFuzzExecutions(result.Stdout)
	}
	if err == nil && (!completed || executions < minimum) {
		err = ErrFuzzCampaign
	}
	if err == nil {
		result.Stdout, result.Stderr = nil, nil
	} else {
		result.Stdout = append([]byte(nil), diagnosticPrefix(result.Stdout)...)
		result.Stderr = append([]byte(nil), diagnosticPrefix(result.Stderr)...)
	}
	return fuzzOutcome{result: result, err: err, executions: executions}
}

func minimumFuzzExecutions(campaign Campaign) uint64 {
	value, found := strings.CutSuffix(campaign.Duration, "x")
	if !found {
		return 1
	}
	executions, err := strconv.ParseUint(value, decimalBase, unsignedIntegerBits)
	if err != nil {
		return 0
	}
	return executions
}

func terminalFuzzExecutions(output []byte) (uint64, bool) {
	line, position := previousOutputLine(output, len(output))
	if !bytes.HasPrefix(line, []byte("ok  \t")) {
		return 0, false
	}
	for position != 0 {
		line, position = previousOutputLine(output, position)
		if !bytes.Equal(line, []byte("PASS")) {
			continue
		}
		terminal, _ := previousOutputLine(output, position)
		if executions, valid := parseFuzzExecutionLine(terminal); valid {
			return executions, true
		}
	}
	return 0, false
}

func previousOutputLine(output []byte, end int) ([]byte, int) {
	for end != 0 && (output[end-1] == '\n' || output[end-1] == '\r') {
		end--
	}
	start := bytes.LastIndexByte(output[:end], '\n') + 1
	line := output[start:end]
	line = bytes.TrimSuffix(line, []byte{'\r'})
	return line, start
}

func parseFuzzExecutionLine(line []byte) (uint64, bool) {
	elapsed, digits, rate, suffix, found := fuzzExecutionFields(line)
	if !found || !validFuzzExecutionFields(elapsed, digits, rate, suffix) {
		return 0, false
	}
	value, err := strconv.ParseUint(string(digits), decimalBase, unsignedIntegerBits)
	return value, err == nil && value != 0
}

func fuzzExecutionFields(line []byte) ([]byte, []byte, []byte, []byte, bool) {
	const prefix = "fuzz: elapsed: "
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return nil, nil, nil, nil, false
	}
	elapsed, after, found := bytes.Cut(line[len(prefix):], []byte(", execs: "))
	if !found {
		return nil, nil, nil, nil, false
	}
	digits, rateAndSuffix, found := bytes.Cut(after, []byte(" ("))
	if !found {
		return nil, nil, nil, nil, false
	}
	rate, suffix, found := bytes.Cut(rateAndSuffix, []byte("/sec)"))
	return elapsed, digits, rate, suffix, found
}

func validFuzzExecutionFields(elapsed, digits, rate, suffix []byte) bool {
	if len(digits) == 0 || len(digits) > 1 && digits[0] == '0' || !canonicalDecimal(rate) || !validFuzzExecutionSuffix(suffix) {
		return false
	}
	if duration, err := time.ParseDuration(string(elapsed)); err != nil || duration < 0 {
		return false
	}
	return true
}

func validFuzzExecutionSuffix(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	const prefix = ", new interesting: "
	interesting, total, found := bytes.Cut(value, []byte(" (total: "))
	interesting = bytes.TrimPrefix(interesting, []byte(prefix))
	total, closed := bytes.CutSuffix(total, []byte(")"))
	return found && closed && bytes.HasPrefix(value, []byte(prefix)) && canonicalDecimal(interesting) && canonicalDecimal(total)
}

func canonicalDecimal(value []byte) bool {
	if len(value) == 0 || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func fuzzCampaignError(control verify.Control, outcome fuzzOutcome) error {
	stdout := diagnosticPrefix(outcome.result.Stdout)
	stderr := diagnosticPrefix(outcome.result.Stderr)
	return fmt.Errorf("%w: %s: %w: stdout %q stderr %q", ErrFuzzCampaign, control.Name, outcome.err, stdout, stderr)
}

func diagnosticPrefix(value []byte) []byte {
	value = bytes.TrimSpace(value)
	if len(value) <= MaxFuzzDiagnosticBytes {
		return value
	}
	marker := []byte("\n... truncated ...\n")
	head := (MaxFuzzDiagnosticBytes - len(marker)) / 2
	tail := MaxFuzzDiagnosticBytes - len(marker) - head
	result := make([]byte, 0, MaxFuzzDiagnosticBytes)
	result = append(result, value[:head]...)
	result = append(result, marker...)
	return append(result, value[len(value)-tail:]...)
}
