// Package goverify discovers and verifies bounded Go repository material
package goverify

import (
	"context"
	"fmt"
	"go/build"
	"go/version"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

// Module describes one admitted Go module
type Module struct {
	Directory  string   // Directory is repository-relative; empty selects the root
	Name       string   // Name is printable output ownership
	Packages   []string // Packages is the ordered package argument set
	Tools      []string // Tools is the ordered tool package set
	Production bool     // Production reports that the package set contains non-test source
}

// Compatibility describes one Go toolchain and its admitted test scopes
type Compatibility struct {
	Version string   // Version is an exact Go toolchain version
	Scopes  []string // Scopes names TestScope values; empty selects every scope
}

// TestScope describes one package set tested and covered together
type TestScope struct {
	Directory    string   // Directory is repository-relative; empty selects the root
	Name         string   // Name is printable output ownership
	Packages     []string // Packages is the ordered package argument set
	SkipCoverage bool     // SkipCoverage omits coverage while retaining race verification
}

// Repository contains the exact material used to construct a verification plan
type Repository struct {
	ID                 string           // ID is the lowercase plan identity
	Self               string           // Self is the absolute secverify executable used by internal controls
	Go                 Tool             // Go executes module, test, coverage, compile and fuzz work
	Linter             Tool             // Linter executes formatting and static analysis
	Vulnerability      Tool             // Vulnerability executes dependency vulnerability analysis
	ExactGo            string           // ExactGo is the required primary Go version
	LinterConfig       string           // LinterConfig is the root configuration path
	Modules            []Module         // Modules is the ordered module inventory
	TestScopes         []TestScope      // TestScopes is the ordered test ownership inventory
	FuzzModules        []FuzzModule     // FuzzModules bounds source target discovery
	Fuzz               Campaign         // Fuzz defines campaign work and ownership
	Compatibility      []Compatibility  // Compatibility lists older toolchains to exercise
	ExtraStatic        []verify.Control // ExtraStatic follows built-in static controls
	ExtraTest          []verify.Control // ExtraTest follows built-in test controls
	AdditionalProfiles []verify.Profile // AdditionalProfiles are selected only by their own identity
}

// RepositoryPlanFor constructs and validates one selected repository profile
func RepositoryPlanFor(ctx context.Context, root string, repository Repository, profileID string) (verify.Plan, error) {
	if ctx == nil || !validRepository(repository) || !validRepositoryGoTool(root, repository.Go) {
		return verify.Plan{}, verify.ErrInvalidPlan
	}
	if err := ctx.Err(); err != nil {
		return verify.Plan{}, err
	}
	profile, err := repositoryProfile(ctx, root, repository, profileID)
	if err != nil {
		return verify.Plan{}, err
	}
	plan := verify.Plan{ID: repository.ID, Profiles: []verify.Profile{profile}}
	if err = verify.Validate(root, plan); err != nil {
		return verify.Plan{}, err
	}
	return plan, nil
}

func validRepositoryGoTool(root string, tool Tool) bool {
	control := verify.Control{ID: "go", Name: "Go", Command: verify.Command{
		Executable: tool.Executable, Environment: tool.Environment, Timeout: tool.Timeout, OutputLimit: tool.OutputLimit,
	}}
	plan := verify.Plan{ID: "repository_go", Profiles: []verify.Profile{{ID: "repository_go", Controls: []verify.Control{control}}}}
	return verify.Validate(root, plan) == nil
}

func repositoryProfile(ctx context.Context, root string, repository Repository, profileID string) (verify.Profile, error) {
	switch profileID {
	case "static":
		return staticRepositoryProfile(repository)
	case "compatibility":
		return requiredRepositoryProfile(profileID, repositoryCompatibilityControls(repository))
	case "test":
		return testRepositoryProfile(repository)
	case "campaign":
		return campaignRepositoryProfile(ctx, root, repository)
	case "fuzz-inventory":
		return fuzzInventoryRepositoryProfile(ctx, root, repository)
	case "benchmark":
		return benchmarkRepositoryProfile(ctx, root, repository)
	case "all":
		return allRepositoryProfile(ctx, root, repository)
	default:
		return repositoryAdditionalProfile(repository.AdditionalProfiles, profileID)
	}
}

func staticRepositoryProfile(repository Repository) (verify.Profile, error) {
	controls, err := repositoryStaticControls(repository)
	return verify.Profile{ID: "static", Controls: controls}, err
}

func testRepositoryProfile(repository Repository) (verify.Profile, error) {
	controls, err := repositoryTestControls(repository)
	if err != nil {
		return verify.Profile{}, err
	}
	return requiredRepositoryProfile("test", append(controls, repository.ExtraTest...))
}

func campaignRepositoryProfile(ctx context.Context, root string, repository Repository) (verify.Profile, error) {
	controls, err := repositoryFuzzControls(ctx, root, repository, true, true, runtime.GOOS)
	return verify.Profile{ID: "campaign", Controls: controls}, err
}

func fuzzInventoryRepositoryProfile(ctx context.Context, root string, repository Repository) (verify.Profile, error) {
	if len(repository.FuzzModules) == 0 {
		return verify.Profile{}, verify.ErrInvalidPlan
	}
	targets, err := DiscoverFuzzTargets(ctx, root, repository.Go, repository.FuzzModules)
	if err != nil {
		return verify.Profile{}, err
	}
	controls, err := repositoryFuzzInventoryControls(repository, targets)
	return verify.Profile{ID: "fuzz-inventory", Controls: controls}, err
}

func benchmarkRepositoryProfile(ctx context.Context, root string, repository Repository) (verify.Profile, error) {
	targets, err := DiscoverTestTargets(ctx, root, repository.Go, repository.FuzzModules)
	if err != nil {
		return verify.Profile{}, err
	}
	if _, err = validBenchmarkTargets(targets.Benchmarks); err != nil {
		return verify.Profile{}, err
	}
	compile, err := repositoryTargetCompileControls(repository, "benchmark")
	if err != nil {
		return verify.Profile{}, err
	}
	operation, err := internalControl(repository, "benchmark", "Benchmark", "__go-benchmark", operationTool(repository.Go), targets.Benchmarks)
	if err != nil {
		return verify.Profile{}, err
	}
	return verify.Profile{ID: "benchmark", Controls: append(compile, withSuccessfulOutput(operation))}, nil
}

func allRepositoryProfile(ctx context.Context, root string, repository Repository) (verify.Profile, error) {
	fuzz, err := repositoryFuzzControls(ctx, root, repository, false, false, runtime.GOOS)
	if err != nil {
		return verify.Profile{}, err
	}
	static, err := repositoryStaticControls(repository)
	if err != nil {
		return verify.Profile{}, err
	}
	tests, err := repositoryTestControls(repository)
	if err != nil {
		return verify.Profile{}, err
	}
	controls := joinControls(static, repositoryCompatibilityControls(repository), tests, repository.ExtraTest, fuzz)
	return verify.Profile{ID: "all", Controls: controls}, nil
}

func requiredRepositoryProfile(id string, controls []verify.Control) (verify.Profile, error) {
	if len(controls) == 0 {
		return verify.Profile{}, verify.ErrInvalidPlan
	}
	return verify.Profile{ID: id, Controls: controls}, nil
}

func repositoryAdditionalProfile(profiles []verify.Profile, id string) (verify.Profile, error) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, nil
		}
	}
	return verify.Profile{}, verify.ErrInvalidPlan
}

func repositoryFuzzControls(ctx context.Context, root string, repository Repository, compile, required bool, goos string) ([]verify.Control, error) {
	if len(repository.FuzzModules) == 0 {
		if required {
			return nil, verify.ErrInvalidPlan
		}
		return nil, nil
	}
	campaign := repositoryCampaign(repository)
	if err := validCampaignOwner(campaign); err != nil {
		return nil, err
	}
	targets, err := DiscoverFuzzTargets(ctx, root, repository.Go, repository.FuzzModules)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		if required {
			return nil, ErrFuzzInventory
		}
		return nil, nil
	}
	if !fuzzSupported(goos) {
		return nil, verify.ErrUnavailable
	}
	control, err := ownedFuzzCampaignControl(repository, campaign, targets)
	if err != nil {
		return nil, err
	}
	controls := []verify.Control{control}
	if compile {
		preflight, compileErr := repositoryTargetCompileControls(repository, "campaign")
		if compileErr != nil {
			return nil, compileErr
		}
		controls = append(preflight, controls...)
	}
	return controls, nil
}

func repositoryFuzzInventoryControls(repository Repository, targets []FuzzTarget) ([]verify.Control, error) {
	controls, err := repositoryTargetCompileControls(repository, "fuzz_inventory")
	if err != nil {
		return nil, err
	}
	operation, err := internalControl(repository, "fuzz_inventory", "Fuzz Inventory", "__go-fuzz-inventory", struct{}{}, targets)
	if err != nil {
		return nil, err
	}
	return append(controls, withSuccessfulOutput(operation)), nil
}

func repositoryTargetCompileControls(repository Repository, prefix string) ([]verify.Control, error) {
	controls := make([]verify.Control, 0, len(repository.Modules))
	for index, module := range repository.Modules {
		if len(module.Packages) == 0 {
			continue
		}
		compile, err := moduleCompileControl(repository, module, index)
		if err != nil {
			return nil, err
		}
		compile.ID = fmt.Sprintf("%s_compile_%02d", prefix, index)
		compile.Name = ownedControlName(module.Directory, module.Name, "Go Compile")
		controls = append(controls, compile)
	}
	return controls, nil
}

func repositoryCampaign(repository Repository) Campaign {
	campaign := repository.Fuzz
	if campaign.Go.Executable == "" {
		campaign.Go = repository.Go
	}
	return campaign
}

func ownedFuzzCampaignControl(repository Repository, campaign Campaign, targets []FuzzTarget) (verify.Control, error) {
	deadline := campaignDeadline(campaign, len(targets))
	campaign.Timeout = repositoryop.InnerTimeout(deadline)
	campaign.Go = operationTool(campaign.Go)
	control, err := internalControl(repository, "fuzz_campaign", "Fuzz Campaign", "__go-fuzz-campaign", campaign, targets)
	if err != nil {
		return verify.Control{}, err
	}
	control = withSuccessfulOutput(control)
	control.Command.Timeout = repositoryop.OuterTimeout(deadline)
	control.Command.Environment = ReplaceEnvironment(control.Command.Environment, "FUZZTIME", campaign.Duration)
	control.Command.Environment = ReplaceEnvironment(control.Command.Environment, "FUZZ_PARALLEL", strconv.Itoa(campaign.Parallelism))
	return control, nil
}

func campaignDeadline(campaign Campaign, targets int) time.Duration {
	if campaign.Timeout != 0 {
		return campaign.Timeout
	}
	jobs := max(1, campaign.Jobs)
	batches := (targets + jobs - 1) / jobs
	maximum := verify.MaxTimeout
	if batches <= 0 || campaign.Go.Timeout > maximum/time.Duration(batches) {
		return maximum
	}
	return campaign.Go.Timeout * time.Duration(batches)
}

func validRepository(repository Repository) bool {
	return repository.ID != "" && repository.Self != "" && version.IsValid(repository.ExactGo) &&
		validToolTimeout(repository.Go) && validRepositoryFuzzTool(repository.Go, repository.Fuzz.Go) &&
		(repository.LinterConfig == ".golangci.yml" || repository.LinterConfig == ".golangci.yaml") &&
		validRepositoryCounts(repository) && validRepositoryMaterial(repository) && validCompatibilityScopes(repository) &&
		validAdditionalProfileIDs(repository.AdditionalProfiles)
}

func validRepositoryFuzzTool(primary, fuzz Tool) bool {
	if fuzz.Executable == "" {
		return true
	}
	return validToolTimeout(fuzz) && fuzz.Executable == primary.Executable && slices.Equal(fuzz.Environment, primary.Environment)
}

func validRepositoryMaterial(repository Repository) bool {
	for _, module := range repository.Modules {
		if !validRepositoryOwner(module.Directory, module.Name, module.Packages) || !validRepositoryTools(module.Tools) ||
			!validModuleArguments(module) {
			return false
		}
	}
	for _, scope := range repository.TestScopes {
		if !validRepositoryOwner(scope.Directory, scope.Name, scope.Packages) || len(scope.Packages) == 0 {
			return false
		}
	}
	return true
}

func validModuleArguments(module Module) bool {
	count := len(module.Packages) + len(module.Tools)
	if len(module.Packages) != 0 && !module.Production {
		count++
	}
	return count <= verify.MaxArguments
}

func validRepositoryOwner(directory, name string, packages []string) bool {
	if !validFuzzText(name) || len(name) > MaxFuzzPathBytes || len(directory) > MaxFuzzPathBytes ||
		directory != "" && !validRelativeDirectory(filepath.FromSlash(directory)) || len(packages) > verify.MaxArguments {
		return false
	}
	return validPackageArguments(packages)
}

func validPackageArguments(packages []string) bool {
	for index, argument := range packages {
		if !validFuzzText(argument) || len(argument) > MaxFuzzPathBytes || argument[0] == '-' || index > 0 && packages[index-1] >= argument {
			return false
		}
	}
	return true
}

func validAdditionalProfileIDs(profiles []verify.Profile) bool {
	seen := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if profile.ID == "" || seen[profile.ID] || builtInProfile(profile.ID) {
			return false
		}
		seen[profile.ID] = true
	}
	return true
}

func builtInProfile(id string) bool {
	switch id {
	case "static", "compatibility", "test", "campaign", "fuzz-inventory", "benchmark", "all":
		return true
	default:
		return false
	}
}

func validRepositoryCounts(repository Repository) bool {
	return len(repository.Modules) > 0 && len(repository.Modules) <= MaxRepositoryModules &&
		len(repository.TestScopes) <= len(repository.Modules) &&
		len(repository.FuzzModules) <= min(len(repository.Modules), MaxFuzzModules) &&
		len(repository.Compatibility) <= verify.MaxProfiles && len(repository.ExtraStatic) <= verify.MaxControls &&
		len(repository.ExtraTest) <= verify.MaxControls && len(repository.AdditionalProfiles) <= verify.MaxProfiles
}

func validCompatibilityScopes(repository Repository) bool {
	scopes := repositoryTestScopes(repository)
	names := make([]string, len(scopes))
	for index, scope := range scopes {
		if slices.Contains(names[:index], scope.Name) {
			return false
		}
		names[index] = scope.Name
	}
	for _, compatibility := range repository.Compatibility {
		if !version.IsValid(compatibility.Version) {
			return false
		}
		for index, name := range compatibility.Scopes {
			if !slices.Contains(names, name) || slices.Contains(compatibility.Scopes[:index], name) {
				return false
			}
		}
	}
	return true
}

func repositoryStaticControls(repository Repository) ([]verify.Control, error) {
	return discoveredRepositoryStaticControls(repository)
}

func discoveredRepositoryStaticControls(repository Repository) ([]verify.Control, error) {
	controls := make([]verify.Control, 0, repositoryFixedStaticControls+len(repository.Modules)*repositoryPackageStaticControls+len(repository.ExtraStatic))
	selfTest := verify.Control{ID: "coverage_self_test", Name: "Coverage Self-Test", Command: verify.Command{
		Executable: repository.Self, Arguments: []string{"__go-coverage-self-test"}, Environment: append([]string(nil), repository.Go.Environment...),
		Input: repositoryop.Empty("__go-coverage-self-test"), Timeout: repository.Go.Timeout, OutputLimit: repository.Go.OutputLimit,
	}}
	controls = append(controls,
		Toolchain(repository.Go, "", repository.ExactGo),
		control("linter_config", "Linter Configuration", repository.Linter, "", "config", "verify", "--config", repository.LinterConfig),
		selfTest,
	)
	for index, module := range repository.Modules {
		controls = append(controls, modulePreparationControls(repository, module, index)...)
	}
	currency, err := moduleCurrencyControl(repository)
	if err != nil {
		return nil, err
	}
	controls = append(controls, currency)
	for index, module := range repository.Modules {
		analysis, analysisErr := moduleAnalysisControls(repository, module, index)
		if analysisErr != nil {
			return nil, analysisErr
		}
		controls = append(controls, analysis...)
	}
	controls = append(controls, repository.ExtraStatic...)
	return controls, nil
}

func modulePreparationControls(repository Repository, module Module, index int) []verify.Control {
	prefix := fmt.Sprintf("module_%02d_", index)
	tidy := ModuleTidy(repository.Go, module.Directory)
	tidy.ID, tidy.Name = prefix+"tidy", ownedControlName(module.Directory, module.Name, "Module Tidy")
	moduleVerify := ModuleVerify(repository.Go, module.Directory)
	moduleVerify.ID, moduleVerify.Name = prefix+"verify", ownedControlName(module.Directory, module.Name, "Module Verification")
	return []verify.Control{tidy, moduleVerify}
}

func moduleAnalysisControls(repository Repository, module Module, index int) ([]verify.Control, error) {
	prefix := fmt.Sprintf("module_%02d_", index)
	if len(module.Packages) == 0 {
		if len(module.Tools) == 0 {
			return nil, nil
		}
		vulnerabilities := Vulnerabilities(repository.Vulnerability, module.Directory, module.Tools...)
		vulnerabilities.ID, vulnerabilities.Name = prefix+"vulnerabilities", ownedControlName(module.Directory, module.Name, "Vulnerabilities")
		return []verify.Control{vulnerabilities}, nil
	}
	config := moduleLinterConfig(module.Directory, repository.LinterConfig)
	fix := Fix(repository.Go, module.Directory, module.Packages...)
	fix.ID, fix.Name = prefix+"fix", ownedControlName(module.Directory, module.Name, "Go Fix")
	format := Format(repository.Linter, module.Directory, "--config", config)
	format.ID, format.Name = prefix+"format", ownedControlName(module.Directory, module.Name, "Go Format")
	vet := Vet(repository.Go, module.Directory, module.Packages...)
	vet.ID, vet.Name = prefix+"vet", ownedControlName(module.Directory, module.Name, "Go Vet")
	lint := Lint(repository.Linter, module.Directory, "--config", config, "./...")
	lint.ID, lint.Name = prefix+"lint", ownedControlName(module.Directory, module.Name, "Go Lint")
	vulnerabilityPackages := append(append([]string(nil), module.Packages...), module.Tools...)
	if !module.Production {
		vulnerabilityPackages = append([]string{"-test"}, vulnerabilityPackages...)
	}
	vulnerabilities := Vulnerabilities(repository.Vulnerability, module.Directory, vulnerabilityPackages...)
	vulnerabilities.ID, vulnerabilities.Name = prefix+"vulnerabilities", ownedControlName(module.Directory, module.Name, "Vulnerabilities")
	compile, err := moduleCompileControl(repository, module, index)
	if err != nil {
		return nil, err
	}
	compile.ID, compile.Name = prefix+"compile", ownedControlName(module.Directory, module.Name, "Go Compile")
	return []verify.Control{fix, format, vet, lint, vulnerabilities, compile}, nil
}

func moduleCurrencyControl(repository Repository) (verify.Control, error) {
	return internalControl(repository, "dependency_currency", "Dependency Currency", "__go-module-currency", operationTool(repository.Go), currencyModules(repository.Modules))
}

func currencyModules(modules []Module) []Module {
	result := make([]Module, len(modules))
	for index, module := range modules {
		result[index] = Module{
			Directory: module.Directory, Name: module.Name, Tools: append([]string(nil), module.Tools...), Production: module.Production,
		}
	}
	return result
}

func ownedControlName(directory, owner, operation string) string {
	if directory == "" {
		return operation
	}
	return operation + " (" + owner + ")"
}

func moduleCompileControl(repository Repository, module Module, index int) (verify.Control, error) {
	return internalControl(repository, "go_compile", "Go Compile", "__go-compile:"+strconv.Itoa(index), operationTool(repository.Go), module)
}

func moduleLinterConfig(directory, config string) string {
	if directory == "" {
		return config
	}
	return strings.Repeat("../", strings.Count(filepath.ToSlash(directory), "/")+1) + config
}

func repositoryCompatibilityControls(repository Repository) []verify.Control {
	scopes := repositoryTestScopes(repository)
	controls := make([]verify.Control, 0, len(repository.Compatibility)*(len(scopes)+1))
	for index, compatibility := range repository.Compatibility {
		tool := repository.Go
		tool.Environment = ReplaceEnvironment(tool.Environment, "GOTOOLCHAIN", compatibility.Version)
		version := Toolchain(tool, "", compatibility.Version)
		version.ID, version.Name = fmt.Sprintf("compatibility_%02d_toolchain", index), compatibility.Version+" Toolchain"
		controls = append(controls, version)
		for scopeIndex, scope := range scopes {
			if len(compatibility.Scopes) != 0 && !slices.Contains(compatibility.Scopes, scope.Name) {
				continue
			}
			test := Test(tool, scope.Directory, scope.Packages...)
			test.ID = fmt.Sprintf("compatibility_%02d_%02d_test", index, scopeIndex)
			test.Name = ownedControlName(scope.Directory, scope.Name, compatibility.Version+" Compatibility")
			controls = append(controls, test)
		}
	}
	return controls
}

func repositoryTestControls(repository Repository) ([]verify.Control, error) {
	scopes := repositoryTestScopes(repository)
	controls := make([]verify.Control, 0, len(scopes)*2)
	for index, scope := range scopes {
		if !scope.SkipCoverage {
			coverage, err := internalControl(repository, fmt.Sprintf("coverage_%02d", index),
				ownedControlName(scope.Directory, scope.Name, "Coverage"), "__go-coverage:"+strconv.Itoa(index), operationTool(repository.Go), scope)
			if err != nil {
				return nil, err
			}
			coverage = withSuccessfulOutput(coverage)
			controls = append(controls, coverage)
		}
		race := Race(repository.Go, scope.Directory, scope.Packages...)
		race.ID, race.Name = fmt.Sprintf("race_%02d", index), ownedControlName(scope.Directory, scope.Name, "Race")
		controls = append(controls, race)
	}
	if len(controls) != 0 && !raceSupported(runtime.GOOS, runtime.GOARCH, repository.Go.Environment) {
		return nil, verify.ErrUnavailable
	}
	return controls, nil
}

func fuzzSupported(goos string) bool {
	switch goos {
	case "darwin", "freebsd", "linux", "windows":
		return true
	default:
		return false
	}
}

func raceSupported(goos, goarch string, environment []string) bool {
	if !cgoEnabled(environment) {
		return false
	}
	switch goos {
	case "linux":
		return goarch == "amd64" || goarch == "arm64" || goarch == "loong64" || goarch == "ppc64le" || goarch == "riscv64" || goarch == "s390x"
	case "darwin":
		return goarch == "amd64" || goarch == "arm64"
	case "freebsd", "netbsd", "windows":
		return goarch == "amd64"
	default:
		return false
	}
}

func cgoEnabled(environment []string) bool {
	for _, value := range environment {
		if enabled, found := strings.CutPrefix(value, "CGO_ENABLED="); found {
			return enabled == "1"
		}
	}
	return build.Default.CgoEnabled
}

func repositoryTestScopes(repository Repository) []TestScope {
	return repository.TestScopes
}

func internalControl[O, M any](repository Repository, id, name, argument string, owner O, material M) (verify.Control, error) {
	input, err := repositoryop.Encode(argument, repositoryop.Specification[O, M]{Owner: owner, Material: material})
	if err != nil {
		return verify.Control{}, err
	}
	return verify.Control{ID: id, Name: name, Command: verify.Command{
		Executable: repository.Self, Arguments: []string{argument}, Environment: repository.Go.Environment,
		Input: input, Timeout: repositoryop.OuterTimeout(repository.Go.Timeout), OutputLimit: repository.Go.OutputLimit,
	}}, nil
}

func operationTool(tool Tool) Tool {
	tool.Timeout = repositoryop.InnerTimeout(tool.Timeout)
	return tool
}

func validToolTimeout(tool Tool) bool {
	return tool.Timeout > 0 && tool.Timeout <= verify.MaxTimeout
}

// ReplaceEnvironment returns an owned environment with one case-insensitive name replacement
func ReplaceEnvironment(environment []string, name, value string) []string {
	prefix := name + "="
	result := make([]string, 0, len(environment)+1)
	replaced := false
	for _, entry := range environment {
		entryName, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(entryName, name) {
			result = append(result, prefix+value)
			replaced = true
		} else {
			result = append(result, entry)
		}
	}
	if !replaced {
		result = append(result, prefix+value)
	}
	return result
}

func joinControls(groups ...[]verify.Control) []verify.Control {
	count := 0
	for _, group := range groups {
		count += len(group)
	}
	result := make([]verify.Control, 0, count)
	for _, group := range groups {
		result = append(result, group...)
	}
	return result
}
