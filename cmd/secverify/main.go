package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	commandline "github.com/secengcommons/cli"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/exactwrite"
	"github.com/secengcommons/verify/internal/safeoutput"
)

const developmentVersion = "development"
const verifyModule = "github.com/secengcommons/verify"
const cliModule = "github.com/secengcommons/cli"
const qualifiedCLIVersion = "v1.1.0"
const proctreeModule = "github.com/secengcommons/proctree"
const qualifiedProctreeVersion = "v1.1.0"
const yamlModule = "go.yaml.in/yaml/v3"
const qualifiedYAMLVersion = "v3.0.5"

var exitProcess = os.Exit
var standardOutput io.Writer = os.Stdout
var standardError io.Writer = os.Stderr

func main() {
	runMain(os.Args, standardOutput, standardError, exitProcess, verify.DispatchProcessOwner)
}

func runMain(
	arguments []string,
	stdout, stderr io.Writer,
	exit func(int),
	dispatch func([]string) (bool, int),
) {
	if dispatchOwnedProcess(arguments, exit, dispatch) {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exit(run(ctx, arguments, stdout, stderr))
}

func dispatchOwnedProcess(arguments []string, exit func(int), dispatch func([]string) (bool, int)) bool {
	handled, code := dispatch(arguments)
	if !handled {
		return false
	}
	exit(code)
	return true
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	return runWith(ctx, arguments, stdout, stderr, os.Getwd, repositoryPlan)
}

func runWith(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	currentDirectory func() (string, error),
	buildPlan func(context.Context, string, string) (verify.Plan, error),
) int {
	return runWithParser(ctx, arguments, stdout, stderr, currentDirectory, buildPlan, commandParser)
}

func runWithParser(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	currentDirectory func() (string, error),
	buildPlan func(context.Context, string, string) (verify.Plan, error),
	buildParser func() (commandline.Parser, error),
) int {
	return runWithParserInput(ctx, arguments, os.Stdin, stdout, stderr, currentDirectory, buildPlan, buildParser)
}

func runWithParserInput(
	ctx context.Context,
	arguments []string,
	input io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	currentDirectory func() (string, error),
	buildPlan func(context.Context, string, string) (verify.Plan, error),
	buildParser func() (commandline.Parser, error),
) int {
	if ctx == nil || len(arguments) == 0 || stdout == nil || stderr == nil {
		return exitInvocation
	}
	if err := ctx.Err(); err != nil {
		return writeFailure(stderr, err)
	}
	if code, handled := runInternalFromCurrent(ctx, arguments[1:], input, stdout, stderr, currentDirectory); handled {
		return code
	}
	parser, err := buildParser()
	if err != nil {
		return writeFailure(stderr, errors.Join(verify.ErrInvocation, err))
	}
	invocation, err := parser.Parse(arguments[1:])
	if err != nil {
		return writeCommandDiagnostic(parser, stderr, err)
	}
	identity := currentIdentity()
	return runCommandInvocation(ctx, invocation, parser, identity, stdout, stderr, currentDirectory, buildPlan)
}

func runCommandInvocation(
	ctx context.Context,
	invocation commandline.Invocation,
	parser commandline.Parser,
	identity executableIdentity,
	stdout, stderr io.Writer,
	currentDirectory func() (string, error),
	buildPlan func(context.Context, string, string) (verify.Plan, error),
) int {
	switch invocation.Action() {
	case commandline.ActionHelp:
		return writeCommandHelp(parser, stdout, invocation.Command())
	case commandline.ActionVersion:
		if err := exactwrite.Bytes(stdout, []byte(identityText(identity))); err != nil {
			return exitInvocation
		}
		return exitPass
	case commandline.ActionRun:
		root, _ := invocation.String("root")
		selected := commandInvocation{root: root, profile: invocation.Command()}
		return runRepositoryInvocation(ctx, selected, identity, stdout, stderr, currentDirectory, buildPlan)
	default:
		return exitInvocation
	}
}

func commandParser() (commandline.Parser, error) {
	return commandline.New(commandDefinition())
}

func commandDefinition() commandline.Definition {
	return commandline.Definition{
		Name: "secverify", Version: true,
		Options: []commandline.Option{{
			Name: "root", Short: "r", Placeholder: "PATH", Summary: "Repository root", Kind: commandline.ValueString, Default: ".",
		}},
		Commands: []commandline.Command{
			{Name: "static", Summary: "Run static verification"},
			{Name: "compatibility", Summary: "Test supported Go versions"},
			{Name: "test", Summary: "Run coverage and race verification"},
			{Name: "campaign", Summary: "Run the bounded fuzz campaign"},
			{Name: "fuzz-inventory", Summary: "List discovered fuzz targets"},
			{Name: "benchmark", Summary: "Run discovered benchmarks"},
			{Name: "all", Summary: "Run the complete local gate"},
		},
	}
}

func writeCommandHelp(parser commandline.Parser, output io.Writer, command string) int {
	help, err := parser.Help(command)
	if err != nil {
		return exitInvocation
	}
	if err = exactwrite.Bytes(output, help); err != nil {
		return exitInvocation
	}
	return exitPass
}

func writeCommandDiagnostic(parser commandline.Parser, output io.Writer, err error) int {
	diagnostic, diagnosticErr := parser.Diagnostic(err)
	if diagnosticErr != nil {
		return exitInvocation
	}
	if diagnosticErr = safeoutput.Write(output, diagnostic); diagnosticErr != nil {
		return exitInvocation
	}
	return exitInvocation
}

func runRepositoryInvocation(
	ctx context.Context,
	invocation commandInvocation,
	identity executableIdentity,
	stdout, stderr io.Writer,
	currentDirectory func() (string, error),
	buildPlan func(context.Context, string, string) (verify.Plan, error),
) int {
	if ctx == nil || stderr == nil {
		return exitInvocation
	}
	if err := writeExecutionIdentity(stdout, identity); err != nil {
		return writeFailure(stderr, errors.Join(verify.ErrInvocation, err))
	}
	workingDirectory, err := currentDirectory()
	if err != nil {
		return writeFailure(stderr, err)
	}
	root, err := resolveRepositoryRoot(workingDirectory, invocation.root)
	if err != nil {
		return writeFailure(stderr, err)
	}
	plan, err := buildPlan(ctx, root, invocation.profile)
	if err != nil {
		return writeFailure(stderr, err)
	}
	return executeVerification(ctx, root, plan, invocation.profile, stdout, stderr)
}

type commandInvocation struct {
	root    string
	profile string
}

func resolveRepositoryRoot(workingDirectory, requested string) (string, error) {
	if !filepath.IsAbs(workingDirectory) {
		return "", verify.ErrInvocation
	}
	root := filepath.Clean(workingDirectory)
	if requested != "" {
		native := filepath.FromSlash(requested)
		if filepath.IsAbs(native) {
			root = filepath.Clean(native)
		} else {
			root = filepath.Clean(filepath.Join(workingDirectory, native))
		}
	}
	resolved, err := canonicalRepositoryRoot(root)
	if err != nil {
		return "", errors.Join(verify.ErrInvocation, err)
	}
	return filepath.Clean(resolved), nil
}

func runInternalFromCurrent(
	ctx context.Context,
	arguments []string,
	input io.Reader,
	stdout, stderr io.Writer,
	currentDirectory func() (string, error),
) (int, bool) {
	operation, handled := classifyRepositoryOperation(arguments)
	if !handled {
		return 0, false
	}
	if operation == repositoryCoverageSelfTest {
		return runInternal(ctx, "", arguments, input, stdout, stderr)
	}
	root, err := currentDirectory()
	if err != nil {
		return writeFailure(stderr, err), true
	}
	root, err = resolveRepositoryRoot(root, "")
	if err != nil {
		return writeFailure(stderr, err), true
	}
	code, _ := runInternal(ctx, root, arguments, input, stdout, stderr)
	return code, true
}

func runInternal(ctx context.Context, root string, arguments []string, input io.Reader, stdout, stderr io.Writer) (int, bool) {
	operation, handled := classifyRepositoryOperation(arguments)
	if !handled {
		return 0, false
	}
	if ctx == nil || input == nil || stdout == nil || stderr == nil {
		return exitInvocation, true
	}
	if err := ctx.Err(); err != nil {
		return writeFailure(stderr, err), true
	}
	return internalResult(stderr, runRepositoryOperation(ctx, root, operation, arguments[0], input, stdout))
}

func internalResult(stderr io.Writer, err error) (int, bool) {
	if err == nil {
		return exitPass, true
	}
	return writeFailure(stderr, err), true
}

func operationError(operation string, err error) error {
	return fmt.Errorf("%s: %w", operation, err)
}
