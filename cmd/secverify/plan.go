package main

import (
	"context"
	"errors"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

const defaultFuzzWork = "100000x"
const defaultFuzzParallelism = 2
const defaultFuzzJobs = 2
const controlTimeout = 5 * time.Minute
const campaignTimeout = 2 * time.Minute
const repositorySourceControlKinds = 4
const golangCILintTool = "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
const govulncheckTool = "golang.org/x/vuln/cmd/govulncheck"
const actionlintTool = "github.com/rhysd/actionlint/cmd/actionlint"
const shellcheckTool = "github.com/wasilibs/go-shellcheck/cmd/shellcheck"

type moduleDiscovery func(context.Context, string, goverify.Tool) (goverify.RepositoryInventory, error)

type toolResolver func(context.Context, string, []goverify.RepositoryModule, string, goverify.Tool) (string, error)

type planOperations struct {
	resolveGo         func() (string, error)
	resolveExecutable func() (string, error)
	absolute          func(string) (string, error)
	resolveCommand    func(string) (string, error)
	discover          moduleDiscovery
	resolveTool       toolResolver
}

type repositoryFoundation struct {
	self        string
	environment []string
	goTool      goverify.Tool
	inventory   goverify.RepositoryInventory
}

func repositoryPlan(ctx context.Context, root, profile string) (verify.Plan, error) {
	return repositoryPlanWith(ctx, root, profile, systemPlanOperations())
}

func systemPlanOperations() planOperations {
	return planOperations{
		resolveGo: goTool, resolveExecutable: os.Executable, absolute: filepath.Abs,
		resolveCommand: executablePath,
		discover:       goverify.DiscoverRepository, resolveTool: goverify.ResolveRepositoryTool,
	}
}

func repositoryPlanWith(
	ctx context.Context,
	root string,
	profile string,
	operations planOperations,
) (verify.Plan, error) {
	repository, err := repositoryConfigurationWith(ctx, root, profile, operations)
	if err != nil {
		return verify.Plan{}, err
	}
	return goverify.RepositoryPlanFor(ctx, root, repository, profile)
}

func repositoryConfigurationWith(
	ctx context.Context,
	root string,
	profile string,
	operations planOperations,
) (goverify.Repository, error) {
	if ctx == nil || !validPlanOperations(operations) {
		return goverify.Repository{}, verify.ErrInvalidPlan
	}
	foundation, err := inspectRepositoryFoundation(ctx, root, operations)
	if err != nil {
		return goverify.Repository{}, err
	}
	modules := foundation.inventory.Modules
	linterTool, vulnerabilityTool, err := selectedAnalysisTools(ctx, root, profile, modules, foundation, operations)
	if err != nil {
		return goverify.Repository{}, err
	}
	gitTool, err := selectedGitTool(profile, foundation, operations)
	if err != nil {
		return goverify.Repository{}, err
	}
	campaign, err := selectedFuzzCampaign(profile, foundation.goTool)
	if err != nil {
		return goverify.Repository{}, err
	}
	extraStatic, err := selectedStaticControls(ctx, root, profile, foundation, gitTool, operations)
	if err != nil {
		return goverify.Repository{}, err
	}
	base := goverify.Repository{
		ID: repositoryIdentifier(modules[0].Path), Self: foundation.self, Go: foundation.goTool, Linter: linterTool, Vulnerability: vulnerabilityTool,
		LinterConfig: foundation.inventory.LinterConfig, Fuzz: campaign, ExtraStatic: extraStatic,
	}
	return goverify.RepositoryFromModules(modules, base)
}

func selectedGitTool(profile string, foundation repositoryFoundation, operations planOperations) (goverify.Tool, error) {
	if len(foundation.inventory.WorkflowFiles) == 0 || profile != "static" && profile != "all" && profile != "workflow-dependencies" {
		return goverify.Tool{}, nil
	}
	executable, err := operations.resolveCommand("git")
	if err != nil {
		return goverify.Tool{}, operationError("resolve Git", err)
	}
	environment := goverify.ReplaceEnvironment(foundation.environment, "GIT_TERMINAL_PROMPT", "0")
	environment = goverify.ReplaceEnvironment(environment, "GCM_INTERACTIVE", "Never")
	environment = goverify.ReplaceEnvironment(environment, "GIT_ASKPASS", "")
	environment = goverify.ReplaceEnvironment(environment, "GIT_CONFIG_NOSYSTEM", "1")
	environment = goverify.ReplaceEnvironment(environment, "GIT_CONFIG_GLOBAL", os.DevNull)
	return goverify.Tool{Executable: executable, Environment: environment, Timeout: controlTimeout, OutputLimit: goverify.MaxRepositoryCommandBytes}, nil
}

func selectedAnalysisTools(
	ctx context.Context,
	root, profile string,
	modules []goverify.RepositoryModule,
	foundation repositoryFoundation,
	operations planOperations,
) (goverify.Tool, goverify.Tool, error) {
	if profile != "static" && profile != "all" {
		return foundation.goTool, foundation.goTool, nil
	}
	return resolveAnalysisTools(ctx, root, modules, foundation, operations)
}

func selectedFuzzCampaign(profile string, tool goverify.Tool) (goverify.Campaign, error) {
	if profile == "campaign" || profile == "all" {
		return fuzzCampaign(tool)
	}
	tool.Timeout = campaignTimeout
	return goverify.Campaign{Go: tool, Duration: defaultFuzzWork, Parallelism: defaultFuzzParallelism, Jobs: defaultFuzzJobs}, nil
}

func selectedStaticControls(
	ctx context.Context,
	root, profile string,
	foundation repositoryFoundation,
	gitTool goverify.Tool,
	operations planOperations,
) ([]verify.Control, error) {
	if profile != "static" && profile != "all" {
		return nil, nil
	}
	controls, err := repositorySourceControls(ctx, root, foundation.inventory, foundation.self, foundation.goTool, gitTool, foundation.environment, operations)
	if err != nil {
		return nil, err
	}
	return controls, nil
}

func validPlanOperations(operations planOperations) bool {
	return operations.resolveGo != nil && operations.resolveExecutable != nil && operations.absolute != nil &&
		operations.resolveCommand != nil && operations.discover != nil && operations.resolveTool != nil
}

func inspectRepositoryFoundation(ctx context.Context, root string, operations planOperations) (repositoryFoundation, error) {
	goExecutable, err := operations.resolveGo()
	if err != nil {
		return repositoryFoundation{}, err
	}
	self, err := operations.resolveExecutable()
	if err != nil {
		return repositoryFoundation{}, operationError("resolve verifier executable", err)
	}
	self, err = operations.absolute(self)
	if err != nil {
		return repositoryFoundation{}, operationError("resolve verifier executable", err)
	}
	environment := selectedEnvironment()
	goTool := goverify.Tool{Executable: goExecutable, Environment: environment, Timeout: controlTimeout, OutputLimit: verify.MaxOutputBytes}
	inventory, err := operations.discover(ctx, root, goTool)
	if err != nil {
		return repositoryFoundation{}, err
	}
	if len(inventory.Modules) == 0 {
		return repositoryFoundation{}, goverify.ErrRepositoryDiscovery
	}
	return repositoryFoundation{self: self, environment: environment, goTool: goTool, inventory: inventory}, nil
}

func resolveAnalysisTools(
	ctx context.Context,
	root string,
	modules []goverify.RepositoryModule,
	foundation repositoryFoundation,
	operations planOperations,
) (goverify.Tool, goverify.Tool, error) {
	linter, err := operations.resolveTool(ctx, root, modules, golangCILintTool, foundation.goTool)
	if err != nil {
		return goverify.Tool{}, goverify.Tool{}, operationError("resolve GolangCI-Lint", err)
	}
	vulnerability, err := operations.resolveTool(ctx, root, modules, govulncheckTool, foundation.goTool)
	if err != nil {
		return goverify.Tool{}, goverify.Tool{}, operationError("resolve Govulncheck", err)
	}
	linterTool := goverify.Tool{Executable: linter, Environment: foundation.environment, Timeout: controlTimeout, OutputLimit: verify.MaxOutputBytes}
	vulnerabilityTool := goverify.Tool{Executable: vulnerability, Environment: foundation.environment, Timeout: controlTimeout, OutputLimit: verify.MaxOutputBytes}
	return linterTool, vulnerabilityTool, nil
}

func repositorySourceControls(
	ctx context.Context,
	root string,
	inventory goverify.RepositoryInventory,
	self string,
	goTool goverify.Tool,
	gitTool goverify.Tool,
	environment []string,
	operations planOperations,
) ([]verify.Control, error) {
	controls := make([]verify.Control, 0, repositorySourceControlKinds)
	needShellcheck := len(inventory.ShellFiles) != 0 || len(inventory.WorkflowFiles) != 0
	shellcheck := ""
	var err error
	if needShellcheck {
		shellcheck, err = operations.resolveTool(ctx, root, inventory.Modules, shellcheckTool, goTool)
		if err != nil {
			return nil, operationError("resolve ShellCheck", err)
		}
	}
	if len(inventory.ShellFiles) != 0 {
		bash, resolveErr := operations.resolveCommand("bash")
		if resolveErr != nil {
			return nil, operationError("resolve Bash", resolveErr)
		}
		syntaxArguments := append([]string{"-n", "--"}, inventory.ShellFiles...)
		controls = append(controls, repositoryCommand("shell_syntax", "Shell Syntax", bash, environment, syntaxArguments))
		shellcheckArguments := append([]string{"--"}, inventory.ShellFiles...)
		controls = append(controls, repositoryCommand("shell_analysis", "Shell Analysis", shellcheck, environment, shellcheckArguments))
	}
	if len(inventory.WorkflowFiles) != 0 {
		actionlint, resolveErr := operations.resolveTool(ctx, root, inventory.Modules, actionlintTool, goTool)
		if resolveErr != nil {
			return nil, operationError("resolve Actionlint", resolveErr)
		}
		arguments := append([]string{"-shellcheck=" + shellcheck}, inventory.WorkflowFiles...)
		admissionOperation := "__go-workflow-admission"
		admissionInput, encodeErr := repositoryop.Encode(admissionOperation,
			repositoryop.Specification[struct{}, []string]{Material: inventory.WorkflowFiles})
		if encodeErr != nil {
			return nil, encodeErr
		}
		admission := repositoryCommand("workflow_admission", "Workflow Admission", self, environment, []string{admissionOperation})
		admission.Command.Input = admissionInput
		controls = append(controls, admission)
		controls = append(controls, repositoryCommand("workflow", "Workflow Syntax", actionlint, environment, arguments))
		operation := "__go-workflow-dependencies"
		innerGit := gitTool
		innerGit.Timeout = repositoryop.InnerTimeout(innerGit.Timeout)
		input, encodeErr := repositoryop.Encode(operation,
			repositoryop.Specification[goverify.Tool, []string]{Owner: innerGit, Material: inventory.WorkflowFiles})
		if encodeErr != nil {
			return nil, encodeErr
		}
		workflowDependencies := repositoryCommand("workflow_dependencies", "Workflow Dependencies", self, environment, []string{operation})
		workflowDependencies.Command.Input = input
		workflowDependencies.Command.Timeout = repositoryop.OuterTimeout(gitTool.Timeout)
		controls = append(controls, workflowDependencies)
	}
	return controls, nil
}

func repositoryCommand(id, name, executable string, environment, arguments []string) verify.Control {
	return verify.Control{ID: id, Name: name, Command: verify.Command{
		Executable: executable, Arguments: arguments, Environment: environment,
		Timeout: controlTimeout, OutputLimit: verify.MaxOutputBytes,
	}}
}

func repositoryIdentifier(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	base := parts[len(parts)-1]
	if len(parts) > 1 && majorVersionElement(base) {
		base = parts[len(parts)-2]
	}
	identifier := strings.Trim(strings.Map(repositoryIdentifierRune, strings.ToLower(base)), "-")
	if identifier == "" {
		return "repository"
	}
	if identifier[0] < 'a' || identifier[0] > 'z' {
		return "repository-" + identifier
	}
	return identifier
}

func repositoryIdentifierRune(character rune) rune {
	if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
		return character
	}
	return '-'
}

func majorVersionElement(value string) bool {
	if len(value) < 2 || value[0] != 'v' || value[1] == '0' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return len(value) > 2 || value[1] >= '2'
}

func goTool() (string, error) {
	return goToolWith(exec.LookPath, filepath.Abs)
}

func goToolWith(lookPath func(string) (string, error), absolute func(string) (string, error)) (string, error) {
	executable, err := lookPath(goExecutableName(os.PathSeparator))
	if err != nil {
		return "", operationError("resolve Go", err)
	}
	executable, err = absolute(executable)
	if err != nil {
		return "", operationError("resolve Go", err)
	}
	return executable, nil
}

func goExecutableName(separator uint8) string {
	if separator == '\\' {
		return "go.exe"
	}
	return "go"
}

func executablePath(name string) (string, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(executable)
}

func selectedEnvironment() []string {
	names := []string{"COMSPEC", "HOME", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"}
	result := make([]string, 0, len(names)+2)
	for _, name := range names {
		if value, found := os.LookupEnv(name); found {
			result = append(result, name+"="+value)
		}
	}
	cgo := "0"
	if build.Default.CgoEnabled {
		cgo = "1"
	}
	return append(result, "CGO_ENABLED="+cgo, "GOARCH="+runtime.GOARCH, "GOFLAGS=", "GOOS="+runtime.GOOS, "GOTOOLCHAIN=auto", "GOWORK=off")
}

func fuzzCampaign(tool goverify.Tool) (goverify.Campaign, error) {
	work := os.Getenv("FUZZTIME")
	if work == "" {
		work = defaultFuzzWork
	}
	parallelism := defaultFuzzParallelism
	if value := os.Getenv("FUZZ_PARALLEL"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return goverify.Campaign{}, errors.Join(goverify.ErrFuzzInventory, err)
		}
		parallelism = parsed
	}
	tool.Timeout = campaignTimeout
	return goverify.Campaign{Go: tool, Duration: work, Parallelism: parallelism, Jobs: defaultFuzzJobs}, nil
}
