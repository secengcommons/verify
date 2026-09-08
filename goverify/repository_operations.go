package goverify

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/exactwrite"
	"github.com/secengcommons/verify/internal/safeoutput"
)

const coverageCommandArguments = 5
const compileCommandArguments = 5

// RunCoverage executes one test scope and requires complete atomic statement coverage
func RunCoverage(ctx context.Context, root string, tool Tool, scope TestScope, output io.Writer) (err error) {
	if ctx == nil || output == nil || !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes {
		return verify.ErrInvocation
	}
	if !validRepositoryOwner(scope.Directory, scope.Name, scope.Packages) || len(scope.Packages) == 0 {
		return verify.ErrInvocation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runCoverageWith(ctx, root, tool, scope, output, repositoryOperations{
		createTemp: os.CreateTemp,
		validate:   verify.Validate,
		run:        proctree.Run,
		open:       os.Open,
		remove:     removeRepositoryCoverage,
		check:      CheckCoverage,
	})
}

// CompileModule compiles tests to the platform null device without executing or retaining binaries
func CompileModule(ctx context.Context, root string, tool Tool, module Module, output io.Writer) (err error) {
	return compileModuleWith(ctx, root, tool, module, output, compileOperations{
		validate: verify.Validate, run: proctree.Run,
	})
}

type compileOperations struct {
	validate func(string, verify.Plan) error
	run      func(context.Context, proctree.Command) (proctree.Result, error)
}

func compileModuleWith(ctx context.Context, root string, tool Tool, module Module, output io.Writer, operations compileOperations) (err error) {
	if ctx == nil || output == nil || !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes ||
		!validRepositoryOwner(module.Directory, module.Name, module.Packages) || len(module.Packages) == 0 {
		return verify.ErrInvocation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	arguments := make([]string, 0, compileCommandArguments+len(module.Packages))
	arguments = append(arguments, "test", "-c", "-o", os.DevNull, "-vet=off")
	arguments = append(arguments, module.Packages...)
	tool.Environment = append([]string(nil), tool.Environment...)
	control := verify.Control{ID: "compile", Name: "Compile", Command: verify.Command{
		Executable: tool.Executable, Arguments: arguments, Directory: module.Directory, Environment: tool.Environment,
		Timeout: tool.Timeout, OutputLimit: tool.OutputLimit,
	}}
	plan := verify.Plan{ID: "compile", Profiles: []verify.Profile{{ID: "compile", Controls: []verify.Control{control}}}}
	if err = operations.validate(root, plan); err != nil {
		return err
	}
	result, runErr := operations.run(ctx, proctree.Command{
		Executable: tool.Executable, Arguments: arguments, Directory: coverageDirectory(root, module.Directory), Environment: tool.Environment,
		StdoutLimit: tool.OutputLimit, StderrLimit: tool.OutputLimit, Timeout: tool.Timeout,
	})
	if err = writeCoverageOutput(output, result); err != nil {
		return err
	}
	if !successfulCoverageRun(result, runErr) {
		return errors.Join(verify.ErrFailed, runErr)
	}
	return ctx.Err()
}

type repositoryOperations struct {
	createTemp func(string, string) (*os.File, error)
	validate   func(string, verify.Plan) error
	run        func(context.Context, proctree.Command) (proctree.Result, error)
	open       func(string) (*os.File, error)
	remove     func(string) error
	check      func(io.Reader) (Coverage, error)
}

func runCoverageWith(
	ctx context.Context,
	root string,
	tool Tool,
	scope TestScope,
	output io.Writer,
	operations repositoryOperations,
) (err error) {
	tool.Environment = append([]string(nil), tool.Environment...)
	file, err := operations.createTemp("", "secverify-coverage-")
	if err != nil {
		return err
	}
	path := file.Name()
	defer func() { err = errors.Join(err, operations.remove(path)) }()
	if err = file.Close(); err != nil {
		return err
	}
	arguments := make([]string, 0, coverageCommandArguments+len(scope.Packages))
	arguments = append(arguments, "test", "-count=1", "-shuffle=on", "-covermode=atomic", "-coverprofile="+path)
	arguments = append(arguments, scope.Packages...)
	control := verify.Control{ID: "coverage", Name: "Coverage", Command: verify.Command{
		Executable: tool.Executable, Arguments: arguments, Directory: scope.Directory, Environment: tool.Environment,
		Timeout: tool.Timeout, OutputLimit: tool.OutputLimit,
	}}
	plan := verify.Plan{ID: "coverage", Profiles: []verify.Profile{{ID: "coverage", Controls: []verify.Control{control}}}}
	if err = operations.validate(root, plan); err != nil {
		return err
	}
	directory := coverageDirectory(root, scope.Directory)
	result, runErr := operations.run(ctx, proctree.Command{
		Executable: tool.Executable, Arguments: arguments, Directory: directory, Environment: tool.Environment,
		StdoutLimit: tool.OutputLimit, StderrLimit: tool.OutputLimit, Timeout: tool.Timeout,
	})
	if err = writeCoverageOutput(output, result); err != nil {
		return err
	}
	if !successfulCoverageRun(result, runErr) {
		return errors.Join(verify.ErrFailed, runErr)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	profile, err := operations.open(path)
	if err != nil {
		return err
	}
	coverage, checkErr := operations.check(profile)
	if err = errors.Join(checkErr, profile.Close()); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return exactwrite.Bytes(output, []byte(CoverageText(coverage)+"\n"))
}

func coverageDirectory(root, directory string) string {
	if directory == "" {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(directory))
}

func successfulCoverageRun(result proctree.Result, err error) bool {
	return err == nil && result.Started && result.ExitCode == 0 && result.Outcome == proctree.OutcomeCompleted
}

func writeCoverageOutput(output io.Writer, result proctree.Result) error {
	if err := writeCoverageStream(output, result.Stdout); err != nil {
		return err
	}
	return writeCoverageStream(output, result.Stderr)
}

func writeCoverageStream(output io.Writer, value []byte) error {
	return safeoutput.Write(output, value)
}

func removeRepositoryCoverage(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// WriteFuzzInventory writes the exact ordered candidate inventory
func WriteFuzzInventory(ctx context.Context, targets []FuzzTarget, output io.Writer) error {
	if ctx == nil || output == nil || len(targets) > MaxFuzzTargets || validCampaignTargets(targets) != nil {
		return ErrFuzzInventory
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := exactwrite.Bytes(output, []byte(target.Package+"/"+target.Name+"\n")); err != nil {
			return err
		}
	}
	return nil
}
