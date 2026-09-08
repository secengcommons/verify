package goverify

import (
	"errors"
	"fmt"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	verify "github.com/secengcommons/verify"
)

const MaxFuzzParallelism = 256
const MaxFuzzExecutions = 1_000_000_000
const MaxFuzzTargets = 1 << 10
const MaxFuzzWorkBytes = 64

var ErrBenchmarkInventory = errors.New("invalid Go benchmark inventory")

// Tool defines one executable and its complete process boundary
type Tool struct {
	Executable  string        // Executable is an absolute regular file or a symlink to one
	Environment []string      // Environment is the complete child environment
	Timeout     time.Duration // Timeout bounds process execution before process-tree cleanup begins
	OutputLimit int           // OutputLimit applies independently to stdout and stderr
}

// Toolchain constructs an exact Go version control
func Toolchain(tool Tool, directory, version string) verify.Control {
	control := exactControl("go_toolchain", "Go Toolchain", tool, directory, []string{"env", "GOVERSION"}, version+"\n")
	control.Command.ExpectedStderr = nil
	return control
}

// ModuleTidy constructs a non-mutating module tidiness control
func ModuleTidy(tool Tool, directory string) verify.Control {
	return control("module_tidy", "Module Tidy", tool, directory, "mod", "tidy", "-diff")
}

// ModuleVerify constructs an exact module-integrity control
func ModuleVerify(tool Tool, directory string) verify.Control {
	return exactControl("module_verify", "Module Verification", tool, directory, []string{"mod", "verify"}, "all modules verified\n")
}

// Fix constructs a non-mutating go fix control
func Fix(tool Tool, directory string, packages ...string) verify.Control {
	return exactControl("go_fix", "Go Fix", tool, directory, append([]string{"fix", "-diff"}, packages...), "")
}

// Vet constructs a go vet control
func Vet(tool Tool, directory string, packages ...string) verify.Control {
	return control("go_vet", "Go Vet", tool, directory, append([]string{"vet"}, packages...)...)
}

// Test constructs a shuffled uncached Go test control
func Test(tool Tool, directory string, packages ...string) verify.Control {
	return control("go_test", "Go Test", tool, directory, append([]string{"test", "-count=1", "-shuffle=on"}, packages...)...)
}

// Race constructs a shuffled uncached race-detector control
func Race(tool Tool, directory string, packages ...string) verify.Control {
	return withSuccessfulOutput(control("go_race", "Go Race", tool, directory,
		append([]string{"test", "-count=1", "-race", "-shuffle=on", "-vet=off"}, packages...)...))
}

// Format constructs a non-mutating GolangCI-Lint formatting control
func Format(tool Tool, directory string, arguments ...string) verify.Control {
	return exactControl("go_format", "Go Format", tool, directory, append([]string{"fmt", "--diff"}, arguments...), "")
}

// Lint constructs a GolangCI-Lint control
func Lint(tool Tool, directory string, arguments ...string) verify.Control {
	return control("go_lint", "Go Lint", tool, directory, append([]string{"run"}, arguments...)...)
}

// Vulnerabilities constructs a Govulncheck control
func Vulnerabilities(tool Tool, directory string, packages ...string) verify.Control {
	return control("go_vulnerabilities", "Go Vulnerabilities", tool, directory, packages...)
}

func benchmarkControls(tool Tool, targets []BenchmarkTarget) ([]verify.Control, error) {
	ordered, err := validBenchmarkTargets(targets)
	if err != nil {
		return nil, err
	}
	return benchmarkControlsForOrdered(tool, ordered)
}

func benchmarkControlsForOrdered(tool Tool, ordered []BenchmarkTarget) ([]verify.Control, error) {
	controls := make([]verify.Control, 0)
	for start := 0; start < len(ordered); {
		end := start + 1
		for end < len(ordered) && ordered[end].Package == ordered[start].Package {
			end++
		}
		control, err := benchmarkControl(tool, ordered[start:end], len(controls))
		if err != nil {
			return nil, err
		}
		controls = append(controls, control)
		start = end
	}
	return controls, nil
}

func validBenchmarkTargets(targets []BenchmarkTarget) ([]BenchmarkTarget, error) {
	if len(targets) == 0 || len(targets) > MaxFuzzTargets {
		return nil, ErrBenchmarkInventory
	}
	ordered := append([]BenchmarkTarget(nil), targets...)
	slices.SortFunc(ordered, compareTarget)
	seen := make(map[string]bool, len(ordered))
	for _, target := range ordered {
		identity := target.Package + "/" + target.Name
		if !validBenchmarkTarget(target) || seen[identity] {
			return nil, ErrBenchmarkInventory
		}
		seen[identity] = true
	}
	return ordered, nil
}

func validBenchmarkTarget(target BenchmarkTarget) bool {
	if !validFuzzText(target.Module) || !validFuzzText(target.Package) || !validFuzzText(target.Directory) ||
		!validFuzzText(target.Argument) || !token.IsIdentifier(target.Name) || !benchmarkName(target.Name) {
		return false
	}
	return validTargetLocation(target.Module, target.Package, target.Directory, target.Argument) &&
		validTargetBounds(target.Module, target.Package, target.Name, target.Directory, target.Argument)
}

func benchmarkControl(tool Tool, targets []BenchmarkTarget, index int) (verify.Control, error) {
	names := make([]string, len(targets))
	for targetIndex, target := range targets {
		names[targetIndex] = target.Name
	}
	pattern := "^(?:" + strings.Join(names, "|") + ")$"
	directory := targets[0].Directory
	if directory == "." {
		directory = ""
	}
	arguments := []string{"test", "-run=^$", "-bench=" + pattern, "-benchmem", targets[0].Argument}
	if argumentBytes(arguments) > verify.MaxArgumentBytes {
		return verify.Control{}, ErrBenchmarkInventory
	}
	return withSuccessfulOutput(control(fmt.Sprintf("benchmark_%03d", index), "Benchmark "+targets[0].Package,
		tool, directory, arguments...)), nil
}

func argumentBytes(arguments []string) int {
	total := 0
	for _, argument := range arguments {
		total += len(argument)
	}
	return total
}

// Campaign defines complete fuzz work across an exact target inventory
type Campaign struct {
	Go          Tool          // Go executes every target
	Duration    string        // Duration is a Go fuzz duration or canonical Nx execution count
	Parallelism int           // Parallelism is passed to each Go fuzz process
	Jobs        int           // Jobs is the campaign worker count; zero selects one
	Timeout     time.Duration // Timeout bounds the complete campaign; zero derives it from per-target bounds
}

func fuzzControls(campaign Campaign, targets []FuzzTarget) ([]verify.Control, error) {
	if err := validCampaign(campaign, targets); err != nil {
		return nil, err
	}
	controls := make([]verify.Control, len(targets))
	for index, target := range targets {
		controls[index] = fuzzControl(campaign, target, index)
	}
	return controls, nil
}

func fuzzControl(campaign Campaign, target FuzzTarget, index int) verify.Control {
	arguments := []string{
		"test", "-run=^$", "-fuzz=^" + target.Name + "$", "-fuzztime=" + campaign.Duration,
		"-parallel=" + strconv.Itoa(campaign.Parallelism), target.Argument,
	}
	identifier := fmt.Sprintf("fuzz_%04d", index)
	name := "Fuzz " + target.Package + "/" + target.Name
	directory := target.Directory
	if directory == "." {
		directory = ""
	}
	return withSuccessfulOutput(control(identifier, name, campaign.Go, directory, arguments...))
}

func validCampaign(campaign Campaign, targets []FuzzTarget) error {
	if err := validCampaignOwner(campaign); err != nil {
		return err
	}
	if len(targets) == 0 || len(targets) > MaxFuzzTargets {
		return ErrFuzzInventory
	}
	return validCampaignTargets(targets)
}

func validCampaignOwner(campaign Campaign) error {
	if !validToolTimeout(campaign.Go) || campaign.Parallelism <= 0 || campaign.Parallelism > MaxFuzzParallelism || campaign.Jobs < 0 || campaign.Jobs > MaxFuzzJobs ||
		campaign.Timeout < 0 || campaign.Timeout > verify.MaxTimeout || campaign.Duration == "" {
		return ErrFuzzInventory
	}
	if err := validFuzzWork(campaign); err != nil {
		return err
	}
	return nil
}

func validFuzzWork(campaign Campaign) error {
	if len(campaign.Duration) > MaxFuzzWorkBytes {
		return ErrFuzzInventory
	}
	if value, found := strings.CutSuffix(campaign.Duration, "x"); found {
		return validFuzzExecutions(value)
	}
	duration, err := time.ParseDuration(campaign.Duration)
	if err != nil || duration <= 0 || duration >= campaign.Go.Timeout {
		return errors.Join(ErrFuzzInventory, err)
	}
	return nil
}

func validFuzzExecutions(value string) error {
	if value == "" || value[0] == '0' {
		return ErrFuzzInventory
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return ErrFuzzInventory
		}
	}
	executions, err := strconv.Atoi(value)
	if err != nil || executions > MaxFuzzExecutions {
		return errors.Join(ErrFuzzInventory, err)
	}
	return nil
}

func validCampaignTargets(targets []FuzzTarget) error {
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		identity := target.Package + "/" + target.Name
		if !validCampaignTarget(target) || seen[identity] {
			return ErrFuzzInventory
		}
		seen[identity] = true
	}
	return nil
}

func validCampaignTarget(target FuzzTarget) bool {
	if !validFuzzText(target.Module) || !validFuzzText(target.Package) || !validFuzzText(target.Directory) ||
		!validFuzzText(target.Argument) || !token.IsIdentifier(target.Name) || !fuzzName(target.Name) ||
		!validTargetBounds(target.Module, target.Package, target.Name, target.Directory, target.Argument) {
		return false
	}
	return validTargetLocation(target.Module, target.Package, target.Directory, target.Argument)
}

func validTargetLocation(module, packageName, directory, argument string) bool {
	if packageName == module {
		return argument == "." && validRelativeDirectory(filepath.FromSlash(directory))
	}
	prefix := module + "/"
	if !strings.HasPrefix(packageName, prefix) {
		return false
	}
	return argument == "./"+strings.TrimPrefix(packageName, prefix) && validRelativeDirectory(filepath.FromSlash(directory))
}

func validTargetBounds(module, packageName, name, directory, argument string) bool {
	return len(module) <= MaxFuzzPathBytes && len(packageName) <= MaxFuzzPathBytes && len(name) <= MaxFuzzPathBytes &&
		len(directory) <= MaxFuzzPathBytes && len(argument) <= MaxFuzzPathBytes
}

func control(id, name string, tool Tool, directory string, arguments ...string) verify.Control {
	return verify.Control{ID: id, Name: name, Command: verify.Command{
		Executable: tool.Executable, Arguments: append([]string(nil), arguments...), Directory: directory,
		Environment: append([]string(nil), tool.Environment...), Timeout: tool.Timeout, OutputLimit: tool.OutputLimit,
	}}
}

func exactControl(id, name string, tool Tool, directory string, arguments []string, expected string) verify.Control {
	result := control(id, name, tool, directory, arguments...)
	result.Command.ExpectedStdout = []byte(expected)
	result.Command.ExpectedStderr = []byte{}
	return result
}

func withSuccessfulOutput(control verify.Control) verify.Control {
	control.Command.ShowSuccessOutput = true
	return control
}
