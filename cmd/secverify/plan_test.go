package main

import (
	"context"
	"errors"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

func TestRepositoryPlanUsesDiscoveredRepository(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	operations := testPlanOperations(t, inventory)
	var names []string
	operations.resolveTool = func(_ context.Context, _ string, _ []goverify.RepositoryModule, name string, _ goverify.Tool) (string, error) {
		names = append(names, name)
		return executable, nil
	}
	plan, err := repositoryPlanWith(t.Context(), root, "static", operations)
	if err != nil || plan.ID != "root" || len(plan.Profiles) != 1 || plan.Profiles[0].ID != "static" {
		t.Fatalf("repositoryPlan = (%#v, %v)", plan, err)
	}
	if !reflect.DeepEqual(names, []string{golangCILintTool, govulncheckTool, shellcheckTool, actionlintTool}) {
		t.Fatalf("resolved tools = %#v", names)
	}
	for _, profile := range plan.Profiles {
		if len(profile.Controls) == 0 {
			t.Fatalf("profile %s is empty", profile.ID)
		}
	}
}

func TestEveryProfileAcceptsRepositoryWorkflows(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	operations := testPlanOperations(t, inventory)
	for _, profile := range []string{"static", "compatibility", "test", "campaign", "fuzz-inventory", "benchmark", "all"} {
		_, err := repositoryPlanWith(t.Context(), root, profile, operations)
		if !profileAvailable(profile) && errors.Is(err, verify.ErrUnavailable) {
			continue
		}
		if err != nil {
			t.Fatalf("profile %q error = %v", profile, err)
		}
	}
}

func profileAvailable(profile string) bool {
	switch profile {
	case "campaign":
		return fuzzAvailable()
	case "test":
		return raceAvailable()
	case "all":
		return fuzzAvailable() && raceAvailable()
	default:
		return true
	}
}

func fuzzAvailable() bool {
	switch runtime.GOOS {
	case "darwin", "freebsd", "linux", "windows":
		return true
	default:
		return false
	}
}

func raceAvailable() bool {
	if !build.Default.CgoEnabled {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	case "freebsd", "netbsd", "windows":
		return runtime.GOARCH == "amd64"
	case "linux":
		switch runtime.GOARCH {
		case "amd64", "arm64", "loong64", "ppc64le", "riscv64", "s390x":
			return true
		}
	}
	return false
}

func TestRepositoryConfigurationRejectsDependencyFailures(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	failure := errors.New("dependency")
	checks := []struct {
		name   string
		mutate func(*planOperations)
	}{
		{name: "Go", mutate: func(value *planOperations) { value.resolveGo = func() (string, error) { return "", failure } }},
		{name: "self", mutate: func(value *planOperations) { value.resolveExecutable = func() (string, error) { return "", failure } }},
		{name: "absolute", mutate: func(value *planOperations) { value.absolute = func(string) (string, error) { return "", failure } }},
		{name: "inventory", mutate: func(value *planOperations) {
			value.discover = func(context.Context, string, goverify.Tool) (goverify.RepositoryInventory, error) {
				return goverify.RepositoryInventory{}, failure
			}
		}},
		{name: "bash", mutate: func(value *planOperations) {
			resolve := value.resolveCommand
			value.resolveCommand = func(name string) (string, error) {
				if name == "bash" {
					return "", failure
				}
				return resolve(name)
			}
		}},
		{name: "Git", mutate: func(value *planOperations) {
			resolve := value.resolveCommand
			value.resolveCommand = func(name string) (string, error) {
				if name == "git" {
					return "", failure
				}
				return resolve(name)
			}
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			operations := testPlanOperations(t, inventory)
			check.mutate(&operations)
			if _, err := repositoryConfigurationWith(t.Context(), root, "static", operations); !errors.Is(err, failure) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, failed := range []string{golangCILintTool, govulncheckTool, shellcheckTool, actionlintTool} {
		t.Run(failed, func(t *testing.T) {
			operations := testPlanOperations(t, inventory)
			resolve := operations.resolveTool
			operations.resolveTool = func(ctx context.Context, root string, modules []goverify.RepositoryModule, name string, tool goverify.Tool) (string, error) {
				if name == failed {
					return "", failure
				}
				return resolve(ctx, root, modules, name, tool)
			}
			if _, err := repositoryConfigurationWith(t.Context(), root, "static", operations); !errors.Is(err, failure) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := repositoryConfigurationWith(nilContext(), root, "static", planOperations{}); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("nil boundary error = %v", err)
	}
	operations := testPlanOperations(t, inventory)
	operations.resolveTool = nil
	if _, err := repositoryConfigurationWith(t.Context(), root, "static", operations); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("nil resolver error = %v", err)
	}
	operations = testPlanOperations(t, goverify.RepositoryInventory{})
	if _, err := repositoryConfigurationWith(t.Context(), root, "static", operations); !errors.Is(err, goverify.ErrRepositoryDiscovery) {
		t.Fatalf("empty inventory error = %v", err)
	}
}

func TestRepositorySourceControlsFollowInventory(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	operations := testPlanOperations(t, inventory)
	goTool := goverify.Tool{Executable: "go"}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	controls, err := repositorySourceControls(t.Context(), root, inventory, executable, goTool, goTool, []string{"ONE=1"}, operations)
	identities := make([]string, len(controls))
	for index, control := range controls {
		identities[index] = control.ID
	}
	wantIdentities := []string{"shell_syntax", "shell_analysis", "workflow_admission", "workflow", "workflow_dependencies"}
	if err != nil || !reflect.DeepEqual(identities, wantIdentities) {
		t.Fatalf("controls = (%#v, %v)", controls, err)
	}
	if !reflect.DeepEqual(controls[0].Command.Arguments, []string{"-n", "--", ".github/scripts/check.sh"}) ||
		!reflect.DeepEqual(controls[1].Command.Arguments, []string{"--", ".github/scripts/check.sh"}) {
		t.Fatalf("shell arguments = (%#v, %#v)", controls[0].Command.Arguments, controls[1].Command.Arguments)
	}
	controls, err = repositorySourceControls(t.Context(), root, goverify.RepositoryInventory{Modules: inventory.Modules}, executable, goTool, goTool, nil, operations)
	if err != nil || len(controls) != 0 {
		t.Fatalf("empty controls = (%#v, %v)", controls, err)
	}
}

func TestRepositorySourceControlsRejectOversizedOperationInput(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	operations := testPlanOperations(t, inventory)
	executable := testExecutablePath(t)
	goTool := goverify.Tool{Executable: executable}
	inventory.WorkflowFiles = []string{strings.Repeat("x", repositoryop.MaxBytes)}
	if _, err := repositorySourceControls(t.Context(), root, inventory, executable, goTool, goTool, nil, operations); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("workflow admission input error = %v", err)
	}
	inventory.WorkflowFiles = []string{".github/workflows/core.yml"}
	gitTool := goverify.Tool{Executable: executable, Environment: []string{strings.Repeat("x", repositoryop.MaxBytes)}}
	if _, err := repositorySourceControls(t.Context(), root, inventory, executable, goTool, gitTool, nil, operations); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("workflow dependency input error = %v", err)
	}
}

func testExecutablePath(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func TestRepositoryPlanRejectsInvalidCampaign(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	t.Setenv("FUZZ_PARALLEL", "invalid")
	if _, err := repositoryPlanWith(t.Context(), root, "campaign", testPlanOperations(t, inventory)); !errors.Is(err, goverify.ErrFuzzInventory) {
		t.Fatalf("parallelism error = %v", err)
	}
}

func TestRepositoryConfigurationResolvesOnlySelectedTools(t *testing.T) {
	root, inventory := repositoryDiscoveryFixture(t)
	for _, profile := range []string{"compatibility", "test", "campaign", "fuzz-inventory", "benchmark"} {
		operations := testPlanOperations(t, inventory)
		operations.resolveTool = func(context.Context, string, []goverify.RepositoryModule, string, goverify.Tool) (string, error) {
			t.Fatalf("%s resolved a static tool", profile)
			return "", errors.New("unreachable")
		}
		operations.resolveCommand = func(string) (string, error) {
			t.Fatalf("%s resolved Bash", profile)
			return "", errors.New("unreachable")
		}
		t.Setenv("FUZZ_PARALLEL", "3")
		repository, err := repositoryConfigurationWith(t.Context(), root, profile, operations)
		if err != nil {
			t.Fatalf("%s repository error = %v", profile, err)
		}
		if profile == "campaign" && repository.Fuzz.Parallelism != 3 {
			t.Fatalf("campaign parallelism = %d", repository.Fuzz.Parallelism)
		}
	}
}

func TestRepositoryPlanObservesCancellationBeforeToolResolution(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := repositoryPlan(cancelled, repositoryRoot(t), "static"); !errors.Is(err, context.Canceled) {
		t.Fatalf("repositoryPlan error = %v", err)
	}
}

func TestGoToolAndEnvironment(t *testing.T) {
	tool, err := goTool()
	if err != nil || !filepath.IsAbs(tool) {
		t.Fatalf("goTool = (%q, %v)", tool, err)
	}
	failure := errors.New("absolute")
	if _, err = goToolWith(func(string) (string, error) { return "go", nil }, func(string) (string, error) { return "", failure }); !errors.Is(err, failure) {
		t.Fatalf("absolute Go error = %v", err)
	}
	if _, err = goToolWith(func(string) (string, error) { return "", failure }, filepath.Abs); !errors.Is(err, failure) {
		t.Fatalf("lookup Go error = %v", err)
	}
	if value, err := executablePath(goExecutableName(os.PathSeparator)); err != nil || !filepath.IsAbs(value) {
		t.Fatalf("executablePath = (%q, %v)", value, err)
	}
	if goExecutableName('/') != "go" || goExecutableName('\\') != "go.exe" {
		t.Fatal("Go executable name differs")
	}
	if _, err := executablePath("secverify-command-that-does-not-exist"); err == nil {
		t.Fatal("missing executable was resolved")
	}
}

func TestSelectedEnvironment(t *testing.T) {
	environment := selectedEnvironment()
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "GOTOOLCHAIN=auto") || !strings.Contains(joined, "GOWORK=off") ||
		!strings.Contains(joined, "GOFLAGS=") || !strings.Contains(joined, "GOOS=") || !strings.Contains(joined, "GOARCH=") ||
		!strings.Contains(joined, "CGO_ENABLED=") {
		t.Fatalf("environment = %#v", environment)
	}
}

func TestPlanHelpers(t *testing.T) {
	tool := goverify.Tool{}
	campaign, err := fuzzCampaign(tool)
	if err != nil || campaign.Duration != defaultFuzzWork || campaign.Parallelism != defaultFuzzParallelism || campaign.Go.Timeout != campaignTimeout {
		t.Fatalf("fuzzCampaign = (%#v, %v)", campaign, err)
	}
}

func TestRepositoryIdentifier(t *testing.T) {
	for modulePath, want := range map[string]string{
		"example.test/verify":       "verify",
		"example.test/strict.json":  "strict-json",
		"example.test/library/v2":   "library",
		"example.test/library/v10":  "library",
		"example.test/library/v01":  "v01",
		"example.test/3d":           "repository-3d",
		"example.test/---":          "repository",
		"example.test/library/v2rc": "v2rc",
	} {
		if got := repositoryIdentifier(modulePath); got != want {
			t.Fatalf("repositoryIdentifier(%q) = %q", modulePath, got)
		}
	}
}

func testPlanOperations(t *testing.T, inventory goverify.RepositoryInventory) planOperations {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goExecutable, err := exec.LookPath(goExecutableName(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	return planOperations{
		resolveGo: func() (string, error) { return goExecutable, nil }, resolveExecutable: os.Executable, absolute: filepath.Abs,
		resolveCommand: func(string) (string, error) { return executable, nil },
		discover: func(context.Context, string, goverify.Tool) (goverify.RepositoryInventory, error) {
			return inventory, nil
		},
		resolveTool: func(context.Context, string, []goverify.RepositoryModule, string, goverify.Tool) (string, error) {
			return executable, nil
		},
	}
}

func repositoryDiscoveryFixture(t *testing.T) (string, goverify.RepositoryInventory) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/root\n\ngo 1.24.0\ntoolchain go1.27.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "tools"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools", "go.mod"), []byte("module example.test/root/tools\n\ngo 1.26.0\ntoolchain go1.27.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fuzz_test.go"), []byte("package root\nimport \"testing\"\nfunc FuzzValue(f *testing.F) {}\nfunc BenchmarkValue(b *testing.B) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modules := []goverify.RepositoryModule{
		{Directory: ".", Path: "example.test/root", GoVersion: "1.24.0", Toolchain: "go1.26.6", HasPackages: true, HasProduction: true},
		{Directory: "tools", Path: "example.test/root/tools", GoVersion: "1.26.0", Toolchain: "go1.26.6", Tools: []string{
			"github.com/golangci/golangci-lint/v2/cmd/golangci-lint", "github.com/rhysd/actionlint/cmd/actionlint",
			"github.com/wasilibs/go-shellcheck/cmd/shellcheck", "golang.org/x/vuln/cmd/govulncheck",
		}},
	}
	return root, goverify.RepositoryInventory{
		Modules: modules, LinterConfig: ".golangci.yml",
		ShellFiles: []string{".github/scripts/check.sh"}, WorkflowFiles: []string{".github/workflows/core.yml"},
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
