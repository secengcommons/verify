package goverify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"unicode"
	"unicode/utf8"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/safeoutput"
)

// RunBenchmarks executes exact grouped targets and requires one result for each declaration
func RunBenchmarks(ctx context.Context, root string, tool Tool, targets []BenchmarkTarget, output io.Writer) error {
	if ctx == nil || output == nil || !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes {
		return verify.ErrInvocation
	}
	ordered, controls, err := admitBenchmarkRun(root, tool, targets)
	if err != nil {
		return err
	}
	targetStart := 0
	for _, control := range controls {
		if err = ctx.Err(); err != nil {
			return err
		}
		targetEnd := targetStart + 1
		for targetEnd < len(ordered) && ordered[targetEnd].Package == ordered[targetStart].Package {
			targetEnd++
		}
		if err = runBenchmarkControl(ctx, root, control, ordered[targetStart:targetEnd], output); err != nil {
			return err
		}
		targetStart = targetEnd
	}
	return ctx.Err()
}

func admitBenchmarkRun(root string, tool Tool, targets []BenchmarkTarget) ([]BenchmarkTarget, []verify.Control, error) {
	ordered, err := validBenchmarkTargets(targets)
	if err != nil {
		return nil, nil, err
	}
	controls, err := benchmarkControlsForOrdered(tool, ordered)
	if err != nil {
		return nil, nil, err
	}
	plan := verify.Plan{ID: "benchmark", Profiles: []verify.Profile{{ID: "benchmark", Controls: controls}}}
	if err = verify.Validate(root, plan); err != nil {
		return nil, nil, err
	}
	return ordered, controls, nil
}

func runBenchmarkControl(ctx context.Context, root string, control verify.Control, targets []BenchmarkTarget, output io.Writer) error {
	return runBenchmarkControlWith(ctx, root, control, targets, output, proctree.Run)
}

func runBenchmarkControlWith(
	ctx context.Context,
	root string,
	control verify.Control,
	targets []BenchmarkTarget,
	output io.Writer,
	run func(context.Context, proctree.Command) (proctree.Result, error),
) error {
	result, runErr := run(ctx, proctree.Command{
		Executable: control.Command.Executable, Arguments: control.Command.Arguments,
		Directory: coverageDirectory(root, control.Command.Directory), Environment: control.Command.Environment,
		StdoutLimit: control.Command.OutputLimit, StderrLimit: control.Command.OutputLimit, Timeout: control.Command.Timeout,
	})
	complete := successfulCoverageRun(result, runErr) && containsBenchmarkResults(result.Stdout, targets)
	outputErr := safeoutput.Write(output, result.Stdout)
	if err := safeoutput.Write(output, result.Stderr); err != nil {
		outputErr = errors.Join(outputErr, err)
	}
	if !complete {
		return errors.Join(verify.ErrFailed, runErr, outputErr)
	}
	return outputErr
}

func containsBenchmarkResults(output []byte, targets []BenchmarkTarget) bool {
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		seen[target.Name] = false
	}
	remaining := len(seen)
	for line := range bytes.SplitSeq(output, []byte{'\n'}) {
		identity, valid := benchmarkResult(line)
		if !valid {
			continue
		}
		name := string(identity)
		if found, exists := seen[name]; exists && !found {
			seen[name] = true
			remaining--
		}
	}
	return remaining == 0 && len(targets) != 0
}

func benchmarkResult(line []byte) ([]byte, bool) {
	name, remainder := benchmarkToken(line)
	if !bytes.HasPrefix(name, []byte("Benchmark")) || len(name) == len("Benchmark") {
		return nil, false
	}
	iterations, remainder := benchmarkToken(remainder)
	if value, valid := unsignedDecimal(iterations); !valid || value == 0 {
		return nil, false
	}
	metrics := 0
	for {
		value, afterValue := benchmarkToken(remainder)
		if len(value) == 0 {
			break
		}
		unit, afterUnit := benchmarkToken(afterValue)
		if !validBenchmarkMetric(value, unit) {
			return nil, false
		}
		metrics++
		remainder = afterUnit
	}
	return benchmarkTargetName(name), metrics != 0
}

func benchmarkTargetName(name []byte) []byte {
	if before, _, found := bytes.Cut(name, []byte{'/'}); found {
		return before
	}
	if separator := bytes.LastIndexByte(name, '-'); separator > len("Benchmark") && canonicalPositiveDecimal(name[separator+1:]) {
		return name[:separator]
	}
	return name
}

func validBenchmarkMetric(value, unit []byte) bool {
	if len(value) == 0 || !validBenchmarkUnit(unit) {
		return false
	}
	return validBenchmarkNumber(value)
}

func validBenchmarkUnit(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for len(value) != 0 {
		character, size := utf8.DecodeRune(value)
		if unicode.IsSpace(character) {
			return false
		}
		value = value[size:]
	}
	return true
}

func validBenchmarkNumber(value []byte) bool {
	if bytes.Equal(value, []byte("NaN")) || bytes.Equal(value, []byte("+Inf")) || bytes.Equal(value, []byte("-Inf")) {
		return true
	}
	if value[0] == '-' {
		value = value[1:]
	}
	whole, fraction, decimal := bytes.Cut(value, []byte{'.'})
	if !canonicalDecimal(whole) {
		return false
	}
	return !decimal || decimalDigits(fraction)
}

func decimalDigits(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalPositiveDecimal(value []byte) bool {
	number, valid := unsignedDecimal(value)
	return valid && number != 0 && (len(value) == 1 || value[0] != '0')
}

func benchmarkToken(value []byte) ([]byte, []byte) {
	value = bytes.TrimLeft(value, " \t")
	for index, character := range value {
		if character == ' ' || character == '\t' || character == '\r' {
			return value[:index], value[index+1:]
		}
	}
	return value, nil
}
