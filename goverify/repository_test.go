package goverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

func TestRepositoryAllProfileAdmitsDeclaredMaxima(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.25.0\ntoolchain go1.27.1\n")
	if err := os.WriteFile(filepath.Join(root, "fuzz_test.go"), []byte("package value\nimport \"testing\"\nfunc FuzzValue(*testing.F) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := testExecutable(t)
	tool := discoveryGoTool(t)
	repository := Repository{
		ID: "maximum", Self: executable, Go: tool, Linter: tool, Vulnerability: tool,
		ExactGo: "go1.26.6", LinterConfig: ".golangci.yml",
		Modules: make([]Module, MaxRepositoryModules), TestScopes: make([]TestScope, MaxRepositoryModules),
		FuzzModules:   []FuzzModule{{Directory: ".", Path: "example.test/root"}},
		Fuzz:          Campaign{Duration: "1x", Parallelism: 1, Jobs: 2},
		Compatibility: make([]Compatibility, verify.MaxProfiles),
	}
	scopes := make([]string, MaxRepositoryModules)
	for index := range MaxRepositoryModules {
		directory := ""
		name := "Root"
		if index != 0 {
			directory = fmt.Sprintf("module-%02d", index)
			name = directory
			if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		repository.Modules[index] = Module{Directory: directory, Name: name, Packages: []string{"./..."}, Production: true}
		repository.TestScopes[index] = TestScope{Directory: directory, Name: name, Packages: []string{"./..."}}
		scopes[index] = name
	}
	for index := range repository.Compatibility {
		repository.Compatibility[index] = Compatibility{Version: fmt.Sprintf("go1.%d.0", index+1), Scopes: scopes}
	}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "all")
	if profileUnavailable("all", repository) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil || len(plan.Profiles) != 1 || len(plan.Profiles[0].Controls) > verify.MaxControls {
		t.Fatalf("maximum all profile = (%d controls, %v)", len(plan.Profiles[0].Controls), err)
	}
}

func TestRepositoryPlanForBuildsOnlyTheSelectedProfile(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module broken.test/module\n\ngo 1.25.0\ntoolchain go1.27.1\n")
	if err := os.WriteFile(filepath.Join(root, "broken_test.go"), []byte("package broken\nfunc broken(\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := testExecutable(t)
	tool := discoveryGoTool(t)
	repository := Repository{
		ID: "broken", Self: executable, Go: tool, Linter: tool, Vulnerability: tool,
		ExactGo: "go1.26.6", LinterConfig: ".golangci.yml", Modules: []Module{{Name: "Root", Packages: []string{"./..."}}},
		TestScopes:  []TestScope{{Name: "Root", Packages: []string{"./..."}}},
		FuzzModules: []FuzzModule{{Directory: ".", Path: "broken.test/module"}}, Fuzz: Campaign{Duration: "1x", Parallelism: 1},
		Compatibility: []Compatibility{{Version: "go1.24.0"}},
	}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "static")
	if err != nil || len(plan.Profiles) != 1 || plan.Profiles[0].ID != "static" {
		t.Fatalf("static plan = (%#v, %v)", plan, err)
	}
	if _, err = RepositoryPlanFor(t.Context(), root, repository, "campaign"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("campaign error = %v", err)
	}
	if _, err = RepositoryPlanFor(t.Context(), root, repository, "benchmark"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("benchmark error = %v", err)
	}
	if _, err = RepositoryPlanFor(t.Context(), root, repository, "all"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("complete error = %v", err)
	}
}

func TestFuzzInventoryDoesNotAcknowledgeInvalidGoSignatures(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/invalid\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := "package invalid\nimport \"testing\"\ntype F struct{}\nfunc FuzzInvalid(*F) {}\nfunc TestValue(*testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(root, "invalid_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := discoveryGoTool(t)
	tool.Environment = []string{"GOTOOLCHAIN=local", "GOWORK=off"}
	repository := Repository{
		ID: "invalid", Self: tool.Executable, Go: tool, ExactGo: "go1.26.6", LinterConfig: ".golangci.yml",
		Modules:     []Module{{Name: "Root", Packages: []string{"./..."}, Production: true}},
		TestScopes:  []TestScope{{Name: "Root", Packages: []string{"./..."}}},
		FuzzModules: []FuzzModule{{Directory: ".", Path: "example.test/invalid"}},
		Fuzz:        Campaign{Duration: "1x", Parallelism: 1},
	}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "fuzz-inventory")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := verify.Execute(t.Context(), root, plan, "fuzz-inventory", &output)
	if !errors.Is(err, verify.ErrFailed) || len(result.Controls) != 1 || strings.Contains(output.String(), "FuzzInvalid") {
		t.Fatalf("invalid signature = (%#v, %q, %v)", result, output.String(), err)
	}
}

func TestRepositoryPlanForRejectsUnknownAndUnavailableProfiles(t *testing.T) {
	root, repository := repositoryFixture(t)
	if _, err := RepositoryPlanFor(nilContext(), root, repository, "static"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "unknown"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("unknown profile error = %v", err)
	}
	repository.Compatibility = nil
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "compatibility"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("unavailable compatibility error = %v", err)
	}
}

func TestRepositoryPlanRejectsInvalidOperationTimeouts(t *testing.T) {
	root, repository := repositoryFixture(t)
	for _, timeout := range []time.Duration{0, -1, verify.MaxTimeout + 1} {
		repository.Go.Timeout = timeout
		for _, profile := range []string{"campaign", "fuzz-inventory", "benchmark"} {
			if _, err := RepositoryPlanFor(t.Context(), root, repository, profile); !errors.Is(err, verify.ErrInvalidPlan) {
				t.Fatalf("%s timeout %s error = %v", profile, timeout, err)
			}
		}
	}
}

func TestRepositoryPlanForCoversEveryProfile(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.AdditionalProfiles = []verify.Profile{{ID: "extended", Controls: repository.ExtraTest}}
	for _, profile := range []string{"compatibility", "test", "campaign", "fuzz-inventory", "benchmark", "all", "extended"} {
		checkRepositoryProfile(t, root, repository, profile)
	}
	if !fuzzSupported(runtime.GOOS) {
		return
	}
	repository.Fuzz.Jobs = 2
	repository.Fuzz.Timeout = time.Minute
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "campaign")
	if err != nil || len(plan.Profiles[0].Controls) != 2 || plan.Profiles[0].Controls[0].ID != "campaign_compile_00" ||
		plan.Profiles[0].Controls[1].ID != "fuzz_campaign" || plan.Profiles[0].Controls[1].Command.Timeout != repositoryop.OuterTimeout(time.Minute) ||
		!slices.Contains(plan.Profiles[0].Controls[1].Command.Environment, "FUZZTIME=1x") ||
		!slices.Contains(plan.Profiles[0].Controls[1].Command.Environment, "FUZZ_PARALLEL=1") {
		t.Fatalf("owned campaign = (%#v, %v)", plan, err)
	}
}

func checkRepositoryProfile(t *testing.T, root string, repository Repository, profile string) {
	t.Helper()
	plan, err := RepositoryPlanFor(t.Context(), root, repository, profile)
	if profileUnavailable(profile, repository) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil || len(plan.Profiles) != 1 || plan.Profiles[0].ID != profile {
		t.Fatalf("profile %q = (%#v, %v)", profile, plan, err)
	}
}

func TestBenchmarkProfileCompilesBeforeExecution(t *testing.T) {
	root, repository := repositoryFixture(t)
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "benchmark")
	if err != nil || len(plan.Profiles[0].Controls) < 2 || plan.Profiles[0].Controls[0].ID != "benchmark_compile_00" {
		t.Fatalf("benchmark preflight = (%#v, %v)", plan, err)
	}
}

func TestRepositoryPlanForRejectsCancellationAndInvalidControls(t *testing.T) {
	root, repository := repositoryFixture(t)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RepositoryPlanFor(cancelled, root, repository, "static"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	repository.ExtraStatic[0].Command.Executable = "relative"
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "static"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("invalid control error = %v", err)
	}
	_, repository = repositoryFixture(t)
	repository.Fuzz.Duration = "invalid"
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "campaign"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("invalid campaign error = %v", err)
	}
}

func TestRepositoryPlanForRejectsMissingBenchmarks(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "fuzz_test.go", "package value\nimport \"testing\"\nfunc FuzzValue(*testing.F) {}\n")
	_, repository := repositoryFixture(t)
	repository.Modules = []Module{{Name: "Root"}}
	repository.FuzzModules = []FuzzModule{{Directory: ".", Path: "example.test/value"}}
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "benchmark"); !errors.Is(err, ErrBenchmarkInventory) {
		t.Fatalf("error = %v", err)
	}
}

func TestDiscoveredModuleControlBoundaries(t *testing.T) {
	repository := Repository{LinterConfig: ".golangci.yml"}
	analysis, err := moduleAnalysisControls(repository, Module{Name: "Empty"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	controls := append(modulePreparationControls(repository, Module{Name: "Empty"}, 0), analysis...)
	if len(controls) != 2 {
		t.Fatalf("empty module controls = %#v", controls)
	}
	tool := Tool{Executable: "go"}
	repository = Repository{Self: "secverify", Go: tool, Linter: tool, Vulnerability: tool, LinterConfig: ".golangci.yml"}
	module := Module{Name: "Tests", Packages: []string{"./..."}}
	analysis, err = moduleAnalysisControls(repository, module, 0)
	if err != nil {
		t.Fatal(err)
	}
	controls = append(modulePreparationControls(repository, module, 0), analysis...)
	if got := controls[len(controls)-1].Command.Arguments; !reflect.DeepEqual(got, []string{"__go-compile:0"}) {
		t.Fatalf("test-only build = %#v", got)
	}
	if got := controls[len(controls)-2].Command.Arguments; !reflect.DeepEqual(got, []string{"-test", "./..."}) {
		t.Fatalf("test-only vulnerabilities = %#v", got)
	}
	if moduleLinterConfig("", ".golangci.yml") != ".golangci.yml" ||
		moduleLinterConfig("tools/workflow", ".golangci.yml") != "../../.golangci.yml" {
		t.Fatal("module linter configuration differs")
	}
}

func TestFuzzInventoryControlsSkipModulesWithoutPackages(t *testing.T) {
	repository := Repository{Modules: []Module{{Name: "Root"}}, Self: "self"}
	targets := []FuzzTarget{{Module: "example.test/module", Package: "example.test/module", Name: "FuzzValue", Directory: ".", Argument: "."}}
	controls, err := repositoryFuzzInventoryControls(repository, targets)
	if err != nil || len(controls) != 1 || controls[0].ID != "fuzz_inventory" {
		t.Fatalf("inventory controls = %#v", controls)
	}
}

func TestRepositoryPlanForUsesTestScopes(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.Modules = append(repository.Modules, Module{Directory: "tools", Name: "tools", Packages: []string{"./..."}})
	repository.TestScopes = []TestScope{
		{Name: "Root", Packages: []string{"./..."}},
		{Directory: "tools", Name: "tools", Packages: []string{"./..."}, SkipCoverage: true},
	}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "test")
	if !raceSupported(runtime.GOOS, runtime.GOARCH, repository.Go.Environment) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil || len(plan.Profiles[0].Controls) != 4 {
		t.Fatalf("scoped test profile = (%#v, %v)", plan.Profiles, err)
	}
}

func TestCoverageOperationRetainsExactScope(t *testing.T) {
	root, repository := repositoryFixture(t)
	scope := TestScope{Name: "Nested", Packages: []string{"./nested/..."}}
	repository.TestScopes = []TestScope{scope}
	repository.Compatibility = nil
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "test")
	if !raceSupported(runtime.GOOS, runtime.GOARCH, repository.Go.Environment) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var specification repositoryop.Specification[Tool, TestScope]
	if err = repositoryop.Decode(bytes.NewReader(plan.Profiles[0].Controls[0].Command.Input), "__go-coverage:0", &specification); err != nil ||
		!reflect.DeepEqual(specification.Material, scope) {
		t.Fatalf("coverage specification = (%#v, %v)", specification, err)
	}
}

func TestRepositoryPlanForSelectsCompatibilityScopes(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.Modules = append(repository.Modules, Module{Directory: "tools", Name: "tools", Packages: []string{"./..."}})
	repository.TestScopes = []TestScope{
		{Name: "Root", Packages: []string{"./..."}},
		{Directory: "tools", Name: "tools", Packages: []string{"./..."}},
	}
	repository.Compatibility[0].Scopes = []string{"Root"}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "compatibility")
	if err != nil || len(plan.Profiles[0].Controls) != 2 {
		t.Fatalf("compatibility controls = (%#v, %v)", plan.Profiles[0].Controls, err)
	}
	repository.Compatibility[0].Scopes = []string{"Missing"}
	if _, err = RepositoryPlanFor(t.Context(), root, repository, "compatibility"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("unknown compatibility scope error = %v", err)
	}
}

func TestRepositoryPlanForRetainsAdditionalProfiles(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.AdditionalProfiles = []verify.Profile{{ID: "extended", Controls: []verify.Control{repository.ExtraTest[0]}}}
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "extended")
	if err != nil || len(plan.Profiles) != 1 || plan.Profiles[0].ID != "extended" {
		t.Fatalf("additional profiles = (%#v, %v)", plan.Profiles, err)
	}
	repository.AdditionalProfiles[0].ID = "static"
	if _, err = RepositoryPlanFor(t.Context(), root, repository, "static"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("duplicate profile error = %v", err)
	}
}

func TestRepositoryPlanForRejectsInvalidConfiguration(t *testing.T) {
	root, repository := repositoryFixture(t)
	for _, mutate := range invalidRepositoryMutations() {
		_, candidate := repositoryFixture(t)
		mutate(&candidate)
		if _, err := RepositoryPlanFor(t.Context(), root, candidate, "all"); !errors.Is(err, verify.ErrInvalidPlan) {
			t.Fatalf("invalid repository error = %v", err)
		}
	}
	repository.ExtraStatic = []verify.Control{{ID: "module_00_fix", Name: "Duplicate", Command: repository.ExtraTest[0].Command}}
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "static"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("duplicate control error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	_, repository = repositoryFixture(t)
	if _, err := RepositoryPlanFor(cancelled, root, repository, "all"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled discovery error = %v", err)
	}
	_, repository = repositoryFixture(t)
	repository.Fuzz.Duration = "invalid"
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "all"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("invalid campaign error = %v", err)
	}
	_, repository = repositoryFixture(t)
	repository.FuzzModules[0].Directory = "missing"
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "all"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("missing fuzz module error = %v", err)
	}
	_, repository = repositoryFixture(t)
	repository.Go.Executable = "relative"
	if _, err := RepositoryPlanFor(t.Context(), root, repository, "all"); !errors.Is(err, verify.ErrInvalidPlan) {
		t.Fatalf("plan admission error = %v", err)
	}
}

func profileUnavailable(profile string, repository Repository) bool {
	switch profile {
	case "campaign":
		return !fuzzSupported(runtime.GOOS)
	case "test":
		return !raceSupported(runtime.GOOS, runtime.GOARCH, repository.Go.Environment)
	case "all":
		return !fuzzSupported(runtime.GOOS) || !raceSupported(runtime.GOOS, runtime.GOARCH, repository.Go.Environment)
	default:
		return false
	}
}

func invalidRepositoryMutations() []func(*Repository) {
	return []func(*Repository){
		func(repository *Repository) { repository.ID = "" },
		func(repository *Repository) { repository.Self = "" },
		func(repository *Repository) { repository.ExactGo = "" },
		func(repository *Repository) { repository.ExactGo = "invalid" },
		func(repository *Repository) {
			repository.Fuzz.Go = repository.Go
			repository.Fuzz.Go.Environment = ReplaceEnvironment(repository.Fuzz.Go.Environment, "GOFLAGS", "-tags=different")
		},
		func(repository *Repository) { repository.LinterConfig = "" },
		func(repository *Repository) { repository.LinterConfig = "../.golangci.yml" },
		func(repository *Repository) { repository.Modules = nil },
		func(repository *Repository) { repository.Modules = make([]Module, MaxRepositoryModules+1) },
		func(repository *Repository) { repository.FuzzModules = make([]FuzzModule, MaxFuzzModules+1) },
		func(repository *Repository) { repository.TestScopes = make([]TestScope, verify.MaxProfiles+1) },
		func(repository *Repository) { repository.Compatibility = make([]Compatibility, verify.MaxProfiles+1) },
		func(repository *Repository) { repository.ExtraStatic = make([]verify.Control, verify.MaxControls+1) },
		func(repository *Repository) { repository.ExtraTest = make([]verify.Control, verify.MaxControls+1) },
		func(repository *Repository) {
			repository.AdditionalProfiles = make([]verify.Profile, verify.MaxProfiles+1)
		},
		func(repository *Repository) { repository.AdditionalProfiles = []verify.Profile{{}} },
		func(repository *Repository) {
			repository.AdditionalProfiles = []verify.Profile{{ID: "extended"}, {ID: "extended"}}
		},
		func(repository *Repository) {
			repository.TestScopes = []TestScope{{Name: "", Packages: []string{"./..."}}}
		},
		func(repository *Repository) {
			repository.TestScopes = []TestScope{{Name: "Root"}}
		},
		func(repository *Repository) {
			repository.Modules = append(repository.Modules, Module{Directory: "other", Name: "Other"})
			repository.TestScopes = []TestScope{{Name: "Root", Packages: []string{"./..."}}, {Name: "Root", Packages: []string{"./..."}}}
		},
		func(repository *Repository) { repository.Modules[0].Packages = []string{"-exec=command"} },
		func(repository *Repository) { repository.Modules[0].Packages = []string{"./z", "./a"} },
		func(repository *Repository) { repository.TestScopes[0].Packages = []string{"./...", "./..."} },
		func(repository *Repository) { repository.Modules[0].Tools = []string{"-mode"} },
		func(repository *Repository) { repository.TestScopes[0].Packages = []string{"-exec=command"} },
		func(repository *Repository) { repository.Modules[0].Directory = "../outside" },
		func(repository *Repository) { repository.Modules[0].Name = "invalid\nname" },
		func(repository *Repository) { repository.Compatibility = []Compatibility{{Version: ""}} },
		func(repository *Repository) { repository.Compatibility = []Compatibility{{Version: "invalid"}} },
		func(repository *Repository) {
			repository.Compatibility = []Compatibility{{Version: "go1.24.0", Scopes: []string{"Root", "Root"}}}
		},
	}
}

func TestRepositoryProfilesFollowAvailableWork(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.TestScopes = nil
	repository.FuzzModules = nil
	repository.Compatibility = nil
	repository.ExtraTest = nil
	for _, profile := range []string{"static", "all"} {
		if _, err := RepositoryPlanFor(t.Context(), root, repository, profile); err != nil {
			t.Fatalf("profile %q error = %v", profile, err)
		}
	}
	for _, profile := range []string{"test", "campaign", "fuzz-inventory", "benchmark"} {
		if _, err := RepositoryPlanFor(t.Context(), root, repository, profile); err == nil {
			t.Fatalf("unavailable profile %q was accepted", profile)
		}
	}

	empty := t.TempDir()
	writeFuzzFile(t, empty, "empty_test.go", "package empty\n")
	repository.FuzzModules = []FuzzModule{{Directory: ".", Path: "example.test/empty"}}
	if controls, err := repositoryFuzzControls(t.Context(), empty, repository, false, false, "windows"); err != nil || len(controls) != 0 {
		t.Fatalf("optional empty campaign = (%#v, %v)", controls, err)
	}
	if _, err := repositoryFuzzControls(t.Context(), empty, repository, true, true, "windows"); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("required empty campaign error = %v", err)
	}
}

func TestModuleArgumentBounds(t *testing.T) {
	module := Module{Packages: make([]string, verify.MaxArguments/2), Tools: make([]string, verify.MaxArguments/2), Production: true}
	if !validModuleArguments(module) {
		t.Fatal("exact module argument bound was rejected")
	}
	module.Production = false
	if validModuleArguments(module) {
		t.Fatal("test-only module argument overflow was accepted")
	}
	module.Production = true
	module.Tools = append(module.Tools, "extra")
	if validModuleArguments(module) {
		t.Fatal("production module argument overflow was accepted")
	}
}

func TestRepositoryOperationEncodingFailures(t *testing.T) {
	huge := strings.Repeat("x", repositoryop.MaxBytes)
	repository := Repository{Self: "secverify", Go: Tool{Executable: "go", Environment: []string{"CGO_ENABLED=1"}, Timeout: time.Minute, OutputLimit: 1024}}
	if _, err := internalControl(repository, "operation", "Operation", "__operation", struct{}{}, huge); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("internal control error = %v", err)
	}
	targets := []FuzzTarget{{Module: huge, Package: huge, Name: "FuzzValue", Directory: ".", Argument: "."}}
	if _, err := repositoryFuzzInventoryControls(repository, targets); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("fuzz inventory control error = %v", err)
	}
	campaign := Campaign{Go: repository.Go, Duration: "1x", Parallelism: 1}
	if _, err := ownedFuzzCampaignControl(repository, campaign, targets); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("fuzz campaign control error = %v", err)
	}
	repository.Modules = []Module{{Name: "Root", Packages: []string{huge}}}
	if _, err := repositoryTargetCompileControls(repository, "compile"); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("compile control error = %v", err)
	}
	if _, err := discoveredRepositoryStaticControls(repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("static control error = %v", err)
	}
	smallTarget := []FuzzTarget{{Module: "example.test/module", Package: "example.test/module", Name: "FuzzValue", Directory: ".", Argument: "."}}
	if _, err := repositoryFuzzInventoryControls(repository, smallTarget); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("fuzz inventory compile error = %v", err)
	}
	if _, err := moduleAnalysisControls(repository, repository.Modules[0], 0); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("module analysis error = %v", err)
	}
	repository.Modules = []Module{{Name: "Root", Tools: []string{huge}}}
	if _, err := discoveredRepositoryStaticControls(repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("currency control error = %v", err)
	}
	repository.Modules = nil
	repository.TestScopes = []TestScope{{Name: "Root", Packages: []string{huge}}}
	if _, err := repositoryTestControls(repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("test control error = %v", err)
	}
	if _, err := testRepositoryProfile(repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("test profile error = %v", err)
	}
}

func TestRepositoryProfileErrorPropagation(t *testing.T) {
	huge := strings.Repeat("x", repositoryop.MaxBytes)
	root := t.TempDir()
	repository := Repository{Self: "secverify", Go: Tool{Environment: []string{"CGO_ENABLED=1"}, Timeout: time.Minute, OutputLimit: 1024}}
	repository.FuzzModules = []FuzzModule{{Directory: "missing", Path: "example.test/missing"}}
	if _, err := fuzzInventoryRepositoryProfile(t.Context(), root, repository); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("fuzz inventory discovery error = %v", err)
	}
	if _, err := allRepositoryProfile(t.Context(), root, repository); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("complete fuzz discovery error = %v", err)
	}
	repository.FuzzModules = nil
	repository.Modules = []Module{{Name: "Root", Packages: []string{huge}}}
	if _, err := allRepositoryProfile(t.Context(), root, repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("complete static error = %v", err)
	}
	repository.Modules = nil
	repository.TestScopes = []TestScope{{Name: "Root", Packages: []string{huge}}}
	if _, err := allRepositoryProfile(t.Context(), root, repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("complete test error = %v", err)
	}
	writeFuzzFile(t, root, "fuzz_test.go", "package value\nimport \"testing\"\nfunc FuzzValue(*testing.F) {}\n")
	repository.Go = discoveryGoTool(t)
	repository.TestScopes = nil
	repository.FuzzModules = []FuzzModule{{Directory: ".", Path: "example.test/value"}}
	repository.Modules = []Module{{Name: "Root", Packages: []string{huge}}}
	repository.Fuzz = Campaign{Go: repository.Go, Duration: "1x", Parallelism: 1}
	if _, err := repositoryFuzzControls(t.Context(), root, repository, true, true, "windows"); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("campaign compile error = %v", err)
	}
}

func TestBenchmarkProfileCompileError(t *testing.T) {
	root := t.TempDir()
	writeFuzzFile(t, root, "value_test.go", "package value\nimport \"testing\"\nfunc BenchmarkValue(*testing.B) {}\n")
	repository := Repository{
		Self: "secverify", Go: discoveryGoTool(t),
		Modules:     []Module{{Name: "Root", Packages: []string{strings.Repeat("x", repositoryop.MaxBytes)}}},
		FuzzModules: []FuzzModule{{Directory: ".", Path: "example.test/value"}},
	}
	if _, err := benchmarkRepositoryProfile(t.Context(), root, repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("benchmark compile error = %v", err)
	}
}

func TestTargetOperationEncodingLimit(t *testing.T) {
	root := t.TempDir()
	var source strings.Builder
	source.WriteString("package value\nimport \"testing\"\n")
	for index := range MaxFuzzTargets {
		fmt.Fprintf(&source, "func FuzzValue%d(*testing.F) {}\nfunc BenchmarkValue%d(*testing.B) {}\n", index, index)
	}
	writeFuzzFile(t, root, "value_test.go", source.String())
	modulePath := strings.Repeat("m", MaxFuzzPathBytes)
	repository := Repository{
		Self: "secverify", Go: discoveryGoTool(t),
		FuzzModules: []FuzzModule{{Directory: ".", Path: modulePath}},
		Fuzz:        Campaign{Duration: "1x", Parallelism: 1},
	}
	if _, err := repositoryFuzzControls(t.Context(), root, repository, false, true, "windows"); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("fuzz operation input error = %v", err)
	}
	if _, err := fuzzInventoryRepositoryProfile(t.Context(), root, repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("fuzz inventory operation input error = %v", err)
	}
	if _, err := benchmarkRepositoryProfile(t.Context(), root, repository); !errors.Is(err, repositoryop.ErrInvalid) {
		t.Fatalf("benchmark operation input error = %v", err)
	}
}

func TestPlatformCapabilities(t *testing.T) {
	for _, test := range []struct {
		goos   string
		goarch string
		race   bool
		fuzz   bool
	}{
		{goos: "linux", goarch: "amd64", race: true, fuzz: true},
		{goos: "linux", goarch: "s390x", race: true, fuzz: true},
		{goos: "darwin", goarch: "arm64", race: true, fuzz: true},
		{goos: "freebsd", goarch: "amd64", race: true, fuzz: true},
		{goos: "netbsd", goarch: "amd64", race: true},
		{goos: "windows", goarch: "arm64", fuzz: true},
		{goos: "aix", goarch: "ppc64"},
	} {
		if got := raceSupported(test.goos, test.goarch, []string{"CGO_ENABLED=1"}); got != test.race {
			t.Fatalf("race %s/%s = %t", test.goos, test.goarch, got)
		}
		if got := fuzzSupported(test.goos); got != test.fuzz {
			t.Fatalf("fuzz %s = %t", test.goos, got)
		}
	}
	if raceSupported("linux", "amd64", []string{"CGO_ENABLED=0"}) {
		t.Fatal("race accepted disabled cgo")
	}
	root, repository := repositoryFixture(t)
	if _, err := repositoryFuzzControls(t.Context(), root, repository, false, true, "aix"); !errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("unsupported campaign error = %v", err)
	}
	repository.Go.Environment = []string{"CGO_ENABLED=0"}
	if _, err := repositoryTestControls(repository); !errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("unsupported race error = %v", err)
	}
}

func nilContext() context.Context { return nil }

func TestRepositoryPlanForUsesOwnedFuzzCampaign(t *testing.T) {
	root, repository := repositoryFixture(t)
	repository.Fuzz.Jobs = 2
	repository.Fuzz.Timeout = 2 * time.Minute
	plan, err := RepositoryPlanFor(t.Context(), root, repository, "campaign")
	if !fuzzSupported(runtime.GOOS) && errors.Is(err, verify.ErrUnavailable) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	profile := plan.Profiles[0]
	if len(profile.Controls) != 2 || profile.Controls[0].ID != "campaign_compile_00" || len(profile.Controls[1].Command.Arguments) != 1 ||
		profile.Controls[1].Command.Arguments[0] != "__go-fuzz-campaign" || profile.Controls[1].Command.Timeout != repositoryop.OuterTimeout(repository.Fuzz.Timeout) ||
		!slices.Contains(profile.Controls[1].Command.Environment, "FUZZTIME=1x") ||
		!slices.Contains(profile.Controls[1].Command.Environment, "FUZZ_PARALLEL=1") {
		t.Fatalf("campaign profile = %#v", profile)
	}
}

func TestOwnedCampaignDerivesAggregateDeadline(t *testing.T) {
	t.Parallel()
	repository := Repository{Go: Tool{Executable: "repository", Timeout: time.Minute}}
	campaign := Campaign{Go: Tool{Executable: "campaign", Timeout: 2 * time.Minute}, Duration: "60s", Parallelism: 4, Jobs: 2}
	control, err := ownedFuzzCampaignControl(repository, campaign, make([]FuzzTarget, 15))
	if err != nil {
		t.Fatal(err)
	}
	if control.Command.Timeout != repositoryop.OuterTimeout(16*time.Minute) || !slices.Contains(control.Command.Environment, "FUZZTIME=60s") ||
		!slices.Contains(control.Command.Environment, "FUZZ_PARALLEL=4") {
		t.Fatalf("owned campaign = %#v", control)
	}
	campaign.Timeout = 3 * time.Minute
	if got := campaignDeadline(campaign, 15); got != 3*time.Minute {
		t.Fatalf("explicit deadline = %s", got)
	}
	campaign.Timeout = 0
	campaign.Go.Timeout = verify.MaxTimeout
	if got := campaignDeadline(campaign, 15); got != verify.MaxTimeout {
		t.Fatalf("bounded deadline = %s", got)
	}
	if got := campaignDeadline(campaign, 0); got != verify.MaxTimeout {
		t.Fatalf("empty deadline = %s", got)
	}
}

func TestReplaceEnvironment(t *testing.T) {
	t.Parallel()
	if value := ReplaceEnvironment([]string{"ONE=1", "GOTOOLCHAIN=local"}, "GOTOOLCHAIN", "go1.24.0"); !reflect.DeepEqual(value, []string{"ONE=1", "GOTOOLCHAIN=go1.24.0"}) {
		t.Fatalf("replacement = %#v", value)
	}
	if value := ReplaceEnvironment([]string{"ONE=1"}, "GOTOOLCHAIN", "go1.24.0"); !reflect.DeepEqual(value, []string{"ONE=1", "GOTOOLCHAIN=go1.24.0"}) {
		t.Fatalf("append = %#v", value)
	}
	if value := ReplaceEnvironment([]string{"gotoolchain=local"}, "GOTOOLCHAIN", "go1.24.0"); !reflect.DeepEqual(value, []string{"GOTOOLCHAIN=go1.24.0"}) {
		t.Fatalf("case-insensitive replacement = %#v", value)
	}
}

func TestRunRepositoryCoverageWith(t *testing.T) {
	environment := []string{"VALUE=before"}
	repository := Repository{Go: Tool{Executable: "go", Environment: environment, Timeout: time.Minute, OutputLimit: 1024}}
	scope := TestScope{Directory: "nested", Name: "Root", Packages: []string{"./..."}}
	operations, path := repositoryOperationsFixture(t, "mode: atomic\nmodule/value.go:1.1,1.2 1 1\n")
	validate := operations.validate
	operations.validate = func(root string, plan verify.Plan) error {
		environment[0] = "VALUE=after"
		return validate(root, plan)
	}
	run := operations.run
	operations.run = func(ctx context.Context, command proctree.Command) (proctree.Result, error) {
		if command.Directory != filepath.Join("root", "nested") || !reflect.DeepEqual(command.Environment, []string{"VALUE=before"}) {
			t.Fatalf("coverage command = %#v", command)
		}
		return run(ctx, command)
	}
	var output bytes.Buffer
	if err := runCoverageWith(t.Context(), "root", repository.Go, scope, &output, operations); err != nil || output.String() != "test output\n1 statement covered across 1 row\n" {
		t.Fatalf("runCoverageWith = (%q, %v)", output.String(), err)
	}
	if _, err := os.Stat(path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coverage residue = %v", err)
	}
}

func TestPublicRepositoryOperations(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/public\n\ngo 1.25.0\n")
	writeDiscoveryFile(t, root, "value file.go", "package public\nfunc Value() int { return 1 }\n")
	writeDiscoveryFile(t, root, "value_test.go", "package public\nimport \"testing\"\nfunc TestValue(t *testing.T) { if Value() != 1 { t.Fatal(Value()) } }\n")
	tool := discoveryGoTool(t)
	module := Module{Name: "Root", Production: true}
	if err := CheckModuleCurrency(t.Context(), root, tool, module); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	scope := TestScope{Name: "Root", Packages: []string{"./..."}}
	if err := RunCoverage(t.Context(), root, tool, scope, &output); err != nil || output.Len() == 0 {
		t.Fatalf("coverage = (%q, %v)", output.String(), err)
	}
}

func TestCompileModuleDoesNotExecuteTestMain(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/compile\n\ngo 1.21\n")
	writeDiscoveryFile(t, root, "value.go", "package compile\n")
	writeDiscoveryFile(t, root, "value_test.go", "package compile\nimport (\"os\"; \"testing\")\nfunc TestMain(m *testing.M) { _ = os.WriteFile(\"executed\", nil, 0o600); os.Exit(m.Run()) }\n")
	tool := discoveryGoTool(t)
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOTOOLCHAIN", "local")
	if err := CompileModule(t.Context(), root, tool, Module{Name: "Root", Packages: []string{"./..."}}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "executed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("TestMain execution evidence = %v", err)
	}
}

func TestCompileAuthenticDuplicateBasenames(t *testing.T) {
	root, err := filepath.Abs("testdata/duplicate-basenames")
	if err != nil {
		t.Fatal(err)
	}
	tool := discoveryGoTool(t)
	module := Module{Name: "Root", Packages: []string{"./..."}}
	if err = CompileModule(t.Context(), root, tool, module, io.Discard); err != nil {
		t.Fatal(err)
	}
	matches, walkErr := retainedTestBinaries(root)
	if walkErr != nil || len(matches) != 0 {
		t.Fatalf("retained compile output = (%#v, %v)", matches, walkErr)
	}
}

func retainedTestBinaries(root string) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".test") || strings.HasSuffix(entry.Name(), ".test.exe")) {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, err
}

func TestCompileModuleRejectsInvalidOwners(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: 1024}
	module := Module{Name: "Root", Packages: []string{"./..."}}
	for _, test := range []struct {
		ctx    context.Context
		root   string
		module Module
		output io.Writer
	}{
		{ctx: nilContext(), root: root, module: module, output: io.Discard},
		{ctx: t.Context(), root: "relative", module: module, output: io.Discard},
		{ctx: t.Context(), root: root, module: Module{Name: "Root"}, output: io.Discard},
		{ctx: t.Context(), root: root, module: module},
	} {
		if err := CompileModule(test.ctx, test.root, tool, test.module, test.output); !errors.Is(err, verify.ErrInvocation) {
			t.Fatalf("invalid compile request = %v", err)
		}
	}
}

func TestCompileModuleOperationFailures(t *testing.T) {
	root := t.TempDir()
	tool := Tool{Executable: "tool", Timeout: time.Minute, OutputLimit: 1024}
	module := Module{Name: "Root", Packages: []string{"./..."}}
	failure := errors.New("failure")
	base := compileOperations{
		validate: func(string, verify.Plan) error { return nil },
		run: func(context.Context, proctree.Command) (proctree.Result, error) {
			return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, nil
		},
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := compileModuleWith(cancelled, root, tool, module, io.Discard, base); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled compile error = %v", err)
	}
	operations := base
	operations.validate = func(string, verify.Plan) error { return failure }
	if err := compileModuleWith(t.Context(), root, tool, module, io.Discard, operations); !errors.Is(err, failure) {
		t.Fatalf("validation error = %v", err)
	}
	operations = base
	operations.run = func(context.Context, proctree.Command) (proctree.Result, error) { return proctree.Result{}, failure }
	if err := compileModuleWith(t.Context(), root, tool, module, io.Discard, operations); !errors.Is(err, verify.ErrFailed) {
		t.Fatalf("run error = %v", err)
	}
	operations = base
	operations.run = func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: []byte("output")}, nil
	}
	if err := compileModuleWith(t.Context(), root, tool, module, repositoryErrorWriter{}, operations); err == nil {
		t.Fatal("writer failure was accepted")
	}
	ctx, cancelAfterRun := context.WithCancel(t.Context())
	operations = base
	operations.run = func(context.Context, proctree.Command) (proctree.Result, error) {
		cancelAfterRun()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, nil
	}
	if err := compileModuleWith(ctx, root, tool, module, io.Discard, operations); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-run cancellation error = %v", err)
	}
}

func TestTemporaryCleanupLifecycle(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.test/cleanup\n\ngo 1.21\n")
	writeDiscoveryFile(t, root, "value.go", "package cleanup\n")
	writeDiscoveryFile(t, root, "value_test.go", "package cleanup\nimport (\"testing\"; \"time\")\nfunc TestBlock(t *testing.T) { time.Sleep(time.Minute) }\n")
	temporary := t.TempDir()
	tool := discoveryGoTool(t)
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOTOOLCHAIN", "local")
	scope := TestScope{Name: "Root", Packages: []string{"./..."}}
	for _, test := range []struct {
		name    string
		timeout time.Duration
		context func() (context.Context, context.CancelFunc)
	}{
		{name: "timeout", timeout: 100 * time.Millisecond, context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(t.Context(), time.Second)
		}},
		{name: "cancellation", timeout: time.Minute, context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(t.Context(), 100*time.Millisecond)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()
			operationTool := tool
			operationTool.Timeout = test.timeout
			operations := repositoryOperations{
				createTemp: func(_, pattern string) (*os.File, error) { return os.CreateTemp(temporary, pattern) },
				validate:   verify.Validate, run: proctree.Run, open: os.Open,
				remove: removeRepositoryCoverage, check: CheckCoverage,
			}
			if err := runCoverageWith(ctx, root, operationTool, scope, io.Discard, operations); err == nil {
				t.Fatal("interrupted coverage passed")
			}
			entries, err := os.ReadDir(temporary)
			if err != nil || len(entries) != 0 {
				t.Fatalf("coverage residue = (%v, %v)", entries, err)
			}
		})
	}
}

func TestRunCoverageRejectsInvalidPublicOwners(t *testing.T) {
	tool := discoveryGoTool(t)
	scope := TestScope{Name: "Root", Packages: []string{"./..."}}
	if err := RunCoverage(nilContext(), t.TempDir(), tool, scope, io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := RunCoverage(t.Context(), t.TempDir(), tool, scope, nil); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("nil output error = %v", err)
	}
	if err := RunCoverage(t.Context(), "relative", tool, scope, io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("relative root error = %v", err)
	}
	scope.Packages = []string{"-exec=command"}
	if err := RunCoverage(t.Context(), t.TempDir(), tool, scope, io.Discard); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("package flag error = %v", err)
	}
	scope.Packages = []string{"./..."}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunCoverage(cancelled, t.TempDir(), tool, scope, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestRunRepositoryCoverageFailures(t *testing.T) {
	failure := errors.New("fixture")
	repository := Repository{Go: Tool{Executable: "go", Timeout: time.Minute, OutputLimit: 1024}}
	scope := TestScope{Name: "Root", Packages: []string{"./..."}}
	tests := []struct {
		name       string
		operations repositoryOperations
		output     io.Writer
	}{
		{name: "create", operations: repositoryOperations{createTemp: func(string, string) (*os.File, error) { return nil, failure }}, output: io.Discard},
		{name: "close", operations: repositoryOperations{createTemp: closedRepositoryTemporary(t), remove: func(string) error { return nil }}, output: io.Discard},
		{name: "validate", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.validate = func(string, verify.Plan) error { return failure }
		}), output: io.Discard},
		{name: "run", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.run = func(context.Context, proctree.Command) (proctree.Result, error) {
				return proctree.Result{Started: true}, failure
			}
		}), output: io.Discard},
		{name: "not started", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.run = func(context.Context, proctree.Command) (proctree.Result, error) { return proctree.Result{}, nil }
		}), output: io.Discard},
		{name: "exit", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.run = func(context.Context, proctree.Command) (proctree.Result, error) {
				return proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure}, nil
			}
		}), output: io.Discard},
		{name: "outcome", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.run = func(context.Context, proctree.Command) (proctree.Result, error) {
				return proctree.Result{Started: true, Outcome: proctree.OutcomeCleanupFailure}, nil
			}
		}), output: io.Discard},
		{name: "open", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.open = func(string) (*os.File, error) { return nil, failure }
		}), output: io.Discard},
		{name: "check", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.check = func(io.Reader) (Coverage, error) { return Coverage{}, failure }
		}), output: io.Discard},
		{name: "output", operations: mutateRepositoryOperations(t, func(*repositoryOperations) {}), output: repositoryErrorWriter{}},
		{name: "remove", operations: mutateRepositoryOperations(t, func(operations *repositoryOperations) {
			operations.remove = func(string) error { return failure }
		}), output: io.Discard},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := runCoverageWith(t.Context(), "root", repository.Go, scope, test.output, test.operations); err == nil {
				t.Fatal("runCoverageWith accepted a failed operation")
			}
		})
	}
	if err := writeCoverageOutput(repositoryErrorWriter{}, proctree.Result{Stderr: []byte("failure")}); err == nil {
		t.Fatal("coverage standard error write was accepted")
	}
	var output bytes.Buffer
	if err := writeCoverageOutput(&output, proctree.Result{Stdout: []byte("stdout"), Stderr: []byte("stderr")}); err != nil ||
		output.String() != "stdout\nstderr\n" {
		t.Fatalf("coverage output = (%q, %v)", output.String(), err)
	}
}

func TestRunRepositoryCoverageObservesCancellation(t *testing.T) {
	repository := Repository{Go: Tool{Executable: "go", Timeout: time.Minute, OutputLimit: 1024}}
	scope := TestScope{Name: "Root", Packages: []string{"./..."}}
	cancelled, cancel := context.WithCancel(t.Context())
	operations := mutateRepositoryOperations(t, func(operations *repositoryOperations) {
		run := operations.run
		operations.run = func(ctx context.Context, command proctree.Command) (proctree.Result, error) {
			result, err := run(ctx, command)
			cancel()
			return result, err
		}
	})
	if err := runCoverageWith(cancelled, "root", repository.Go, scope, io.Discard, operations); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled coverage error = %v", err)
	}
	postCheck, cancelPostCheck := context.WithCancel(t.Context())
	operations = mutateRepositoryOperations(t, func(operations *repositoryOperations) {
		check := operations.check
		operations.check = func(reader io.Reader) (Coverage, error) {
			result, err := check(reader)
			cancelPostCheck()
			return result, err
		}
	})
	if err := runCoverageWith(postCheck, "root", repository.Go, scope, io.Discard, operations); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-check cancellation error = %v", err)
	}
}

func TestRemoveRepositoryCoverageRejectsDirectory(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "retained"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeRepositoryCoverage(directory); err == nil {
		t.Fatal("removeRepositoryCoverage removed a non-empty directory")
	}
}

func TestWriteFuzzInventoryFailures(t *testing.T) {
	targets := []FuzzTarget{{
		Module: "example.test/module", Package: "example.test/module", Name: "FuzzValue", Directory: ".", Argument: ".",
	}}
	if err := WriteFuzzInventory(t.Context(), nil, io.Discard); err != nil {
		t.Fatalf("empty inventory error = %v", err)
	}
	if err := WriteFuzzInventory(t.Context(), make([]FuzzTarget, MaxFuzzTargets+1), io.Discard); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("oversized inventory error = %v", err)
	}
	if err := WriteFuzzInventory(t.Context(), targets, repositoryErrorWriter{}); err == nil {
		t.Fatal("inventory accepted writer failure")
	}
	if err := WriteFuzzInventory(nilContext(), targets, io.Discard); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := WriteFuzzInventory(t.Context(), targets, nil); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("nil output error = %v", err)
	}
	invalid := append([]FuzzTarget(nil), targets...)
	invalid[0].Package = "invalid\npackage"
	if err := WriteFuzzInventory(t.Context(), invalid, io.Discard); !errors.Is(err, ErrFuzzInventory) {
		t.Fatalf("invalid target error = %v", err)
	}
	var output bytes.Buffer
	if err := WriteFuzzInventory(t.Context(), targets, &output); err != nil || output.String() != "example.test/module/FuzzValue\n" {
		t.Fatalf("inventory output = (%q, %v)", output.String(), err)
	}
}

func TestWriteFuzzInventoryCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	targets := []FuzzTarget{
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzValue", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzOther", Directory: ".", Argument: "."},
	}
	if err := WriteFuzzInventory(cancelled, targets[:1], io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled inventory error = %v", err)
	}
	if err := WriteFuzzInventory(cancelled, nil, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled empty inventory error = %v", err)
	}
	var output bytes.Buffer
	if err := WriteFuzzInventory(&stagedContext{Context: t.Context(), failAt: 3}, targets, &output); !errors.Is(err, context.Canceled) || output.Len() == 0 {
		t.Fatalf("mid-inventory cancellation = (%q, %v)", output.String(), err)
	}
}

func repositoryFixture(t *testing.T) (string, Repository) {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	executable := testExecutable(t)
	temporary := t.TempDir()
	tool := discoveryGoTool(t)
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOCOVERDIR", temporary)
	tool.Environment = ReplaceEnvironment(tool.Environment, "TEMP", temporary)
	tool.Environment = ReplaceEnvironment(tool.Environment, "TMP", temporary)
	extra := verify.Control{ID: "extra", Name: "Extra", Command: verify.Command{
		Executable: executable, Arguments: []string{"-test.run=^$"}, Environment: tool.Environment,
		Timeout: time.Minute, OutputLimit: 1 << 20,
	}}
	extraTest := extra
	extraTest.ID, extraTest.Name = "extra_test", "Extra Test"
	return root, Repository{
		ID: "repository", Self: executable, Go: tool, Linter: tool, Vulnerability: tool,
		ExactGo: "go1.26.6", LinterConfig: ".golangci.yml",
		Modules:     []Module{{Directory: "", Name: "Root", Packages: []string{"./..."}}},
		TestScopes:  []TestScope{{Name: "Root", Packages: []string{"./..."}}},
		FuzzModules: []FuzzModule{{Directory: ".", Path: "github.com/secengcommons/verify"}},
		Fuzz:        Campaign{Duration: "1x", Parallelism: 1}, Compatibility: []Compatibility{{Version: "go1.24.0"}},
		ExtraStatic: []verify.Control{extra}, ExtraTest: []verify.Control{extraTest},
	}
}

func repositoryOperationsFixture(t *testing.T, profile string) (repositoryOperations, func() string) {
	t.Helper()
	directory := t.TempDir()
	path := ""
	operations := repositoryOperations{
		createTemp: func(string, string) (*os.File, error) {
			file, err := os.CreateTemp(directory, "coverage-")
			if err == nil {
				path = file.Name()
			}
			return file, err
		},
		validate: func(string, verify.Plan) error { return nil },
		run: func(_ context.Context, command proctree.Command) (proctree.Result, error) {
			argument := command.Arguments[4]
			err := os.WriteFile(strings.TrimPrefix(argument, "-coverprofile="), []byte(profile), 0o600)
			return proctree.Result{Started: true, Stdout: []byte("test output\n"), Outcome: proctree.OutcomeCompleted}, err
		},
		open: os.Open, remove: removeRepositoryCoverage, check: CheckCoverage,
	}
	return operations, func() string { return path }
}

func mutateRepositoryOperations(t *testing.T, mutate func(*repositoryOperations)) repositoryOperations {
	t.Helper()
	operations, _ := repositoryOperationsFixture(t, "mode: atomic\nmodule/value.go:1.1,1.2 1 1\n")
	mutate(&operations)
	return operations
}

func closedRepositoryTemporary(t *testing.T) func(string, string) (*os.File, error) {
	t.Helper()
	return func(string, string) (*os.File, error) {
		file, err := os.CreateTemp(t.TempDir(), "closed-")
		if err != nil {
			return nil, err
		}
		if err = file.Close(); err != nil {
			return nil, err
		}
		return file, nil
	}
}

type repositoryErrorWriter struct{}

func (repositoryErrorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }
