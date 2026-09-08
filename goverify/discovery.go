package goverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

const repositoryFixedStaticControls = 4
const repositoryPackageStaticControls = 8
const MaxRepositoryModules = verify.MaxProfiles / 2
const MaxRepositoryEntries = 100_000
const MaxRepositoryCommandBytes = 1 << 20
const MaxRepositorySources = verify.MaxArguments - 2
const MaxRepositorySourceBytes = verify.MaxArgumentBytes - verify.MaxPathBytes
const goVersionComponents = 3

var ErrRepositoryDiscovery = errors.New("invalid Go repository inventory")

// RepositoryModule is one discovered module before plan construction
type RepositoryModule struct {
	Directory     string   // Directory is repository-relative; dot selects the root
	Path          string   // Path is the declared module path
	GoVersion     string   // GoVersion is the language version without the go prefix
	Toolchain     string   // Toolchain is the declared toolchain or nested preference
	Tools         []string // Tools is the ordered tool directive inventory
	HasPackages   bool     // HasPackages reports at least one owned Go source file
	HasProduction bool     // HasProduction reports at least one non-test Go source file
}

// RepositoryInventory is the complete bounded discovery result
type RepositoryInventory struct {
	Modules       []RepositoryModule // Modules follows repository traversal order
	LinterConfig  string             // LinterConfig is the unique root GolangCI-Lint file
	ShellFiles    []string           // ShellFiles is the ordered .sh inventory
	WorkflowFiles []string           // WorkflowFiles is the ordered GitHub workflow inventory
}

type moduleDescription struct {
	Module struct {
		Path string
	}
	Go        string
	Toolchain string
	Tool      []struct {
		Path string
	}
	Replace []struct{}
}

type repositoryModuleRunner func(context.Context, proctree.Command) (proctree.Result, error)

// DiscoverRepository inventories an absolute repository root without following symlinks
func DiscoverRepository(ctx context.Context, root string, tool Tool) (RepositoryInventory, error) {
	return discoverRepositoryWith(ctx, root, tool, proctree.Run)
}

func discoverRepositoryWith(
	ctx context.Context,
	root string,
	tool Tool,
	runner repositoryModuleRunner,
) (RepositoryInventory, error) {
	if ctx == nil {
		return RepositoryInventory{}, ErrRepositoryDiscovery
	}
	if err := ctx.Err(); err != nil {
		return RepositoryInventory{}, errors.Join(ErrRepositoryDiscovery, err)
	}
	discovered, err := discoverRepositoryFiles(ctx, root)
	if err != nil {
		return RepositoryInventory{}, fmt.Errorf("discover repository files: %w", err)
	}
	modules := make([]RepositoryModule, len(discovered.directories))
	for index, directory := range discovered.directories {
		modules[index], err = inspectRepositoryModule(ctx, root, directory, tool, runner)
		if err != nil {
			return RepositoryInventory{}, fmt.Errorf("inspect repository module %s: %w", directory, err)
		}
	}
	if err = validateRepositoryModules(modules); err != nil {
		return RepositoryInventory{}, fmt.Errorf("validate repository modules: %w", err)
	}
	if err = classifyRepositoryPackages(ctx, modules, discovered.goFiles); err != nil {
		return RepositoryInventory{}, fmt.Errorf("classify repository packages: %w", err)
	}
	return RepositoryInventory{
		Modules: modules, LinterConfig: discovered.linterConfig,
		ShellFiles: discovered.shellFiles, WorkflowFiles: discovered.workflowFiles,
	}, nil
}

type repositoryFiles struct {
	directories   []string
	linterConfig  string
	shellFiles    []string
	workflowFiles []string
	goFiles       []string
}

func discoverRepositoryFiles(ctx context.Context, root string) (files repositoryFiles, err error) {
	if !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes {
		return repositoryFiles{}, ErrRepositoryDiscovery
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return repositoryFiles{}, errors.Join(ErrRepositoryDiscovery, err)
	}
	defer func() { err = errors.Join(err, opened.Close()) }()
	owner := repositoryFileInventory{ctx: ctx, root: opened, directories: make([]string, 0)}
	if err = owner.walk("."); err != nil {
		return repositoryFiles{}, err
	}
	if len(owner.directories) == 0 || owner.directories[0] != "." {
		return repositoryFiles{}, ErrRepositoryDiscovery
	}
	if owner.linterConfig == "" {
		return repositoryFiles{}, ErrRepositoryDiscovery
	}
	slices.Sort(owner.shellFiles)
	slices.Sort(owner.workflowFiles)
	return repositoryFiles{
		directories: owner.directories, linterConfig: owner.linterConfig,
		shellFiles: owner.shellFiles, workflowFiles: owner.workflowFiles, goFiles: owner.goFiles,
	}, nil
}

type repositoryFileInventory struct {
	ctx           context.Context
	root          *os.Root
	entries       int
	directories   []string
	shellFiles    []string
	shellBytes    int
	workflowFiles []string
	workflowBytes int
	linterConfig  string
	goFiles       []string
}

func (owner *repositoryFileInventory) walk(directory string) error {
	if err := owner.ctx.Err(); err != nil {
		return errors.Join(ErrRepositoryDiscovery, err)
	}
	entries, err := owner.readDirectory(directory)
	if err != nil {
		return err
	}
	if containsRepositoryModule(entries) {
		if err = owner.addModule(directory); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if err = owner.ctx.Err(); err != nil {
			return errors.Join(ErrRepositoryDiscovery, err)
		}
		if err = owner.walkEntry(directory, entry); err != nil {
			return err
		}
	}
	return nil
}

func (owner *repositoryFileInventory) readDirectory(directory string) ([]os.DirEntry, error) {
	opened, err := owner.root.Open(directory)
	if err != nil {
		return nil, errors.Join(ErrRepositoryDiscovery, err)
	}
	remaining := MaxRepositoryEntries - owner.entries
	entries, readErr := readBoundedDirectory(owner.ctx, opened.ReadDir, opened.Close, remaining, ErrRepositoryDiscovery)
	owner.entries += len(entries)
	if readErr != nil {
		return nil, readErr
	}
	return entries, nil
}

func containsRepositoryModule(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if entry.Name() == "go.mod" && entry.Type().IsRegular() {
			return true
		}
	}
	return false
}

func (owner *repositoryFileInventory) addModule(directory string) error {
	if len(owner.directories) == MaxRepositoryModules {
		return ErrRepositoryDiscovery
	}
	owner.directories = append(owner.directories, filepath.ToSlash(directory))
	return nil
}

func (owner *repositoryFileInventory) walkEntry(directory string, entry os.DirEntry) error {
	if err := owner.ctx.Err(); err != nil {
		return errors.Join(ErrRepositoryDiscovery, err)
	}
	if !validFuzzText(entry.Name()) {
		return ErrRepositoryDiscovery
	}
	name := filepath.Join(directory, entry.Name())
	if len(filepath.ToSlash(name)) > MaxFuzzPathBytes {
		return ErrRepositoryDiscovery
	}
	if entry.Type()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic link %s", ErrRepositoryDiscovery, name)
	}
	if entry.Type().IsRegular() {
		return owner.addSourceFile(directory, entry.Name())
	}
	if !entry.IsDir() {
		return fmt.Errorf("%w: unsupported file %s", ErrRepositoryDiscovery, name)
	}
	if ignoredRepositoryDirectory(entry.Name()) {
		return nil
	}
	return owner.walk(name)
}

func (owner *repositoryFileInventory) addSourceFile(directory, name string) error {
	relative := filepath.ToSlash(filepath.Join(directory, name))
	relative = strings.TrimPrefix(relative, "./")
	if err := owner.addLinterConfiguration(directory, name, relative); err != nil {
		return err
	}
	if strings.HasSuffix(name, ".go") {
		owner.goFiles = append(owner.goFiles, relative)
	}
	if strings.HasSuffix(name, ".sh") {
		if err := addRepositorySource(&owner.shellFiles, &owner.shellBytes, relative); err != nil {
			return err
		}
	}
	if filepath.ToSlash(directory) == ".github/workflows" && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		return addRepositorySource(&owner.workflowFiles, &owner.workflowBytes, relative)
	}
	return nil
}

func (owner *repositoryFileInventory) addLinterConfiguration(directory, name, relative string) error {
	if directory == "." && (name == ".golangci.yml" || name == ".golangci.yaml") {
		if owner.linterConfig != "" {
			return ErrRepositoryDiscovery
		}
		owner.linterConfig = relative
	}
	return nil
}

func addRepositorySource(files *[]string, bytes *int, value string) error {
	if len(value) > MaxRepositorySourceBytes-*bytes || len(*files) == MaxRepositorySources {
		return ErrRepositoryDiscovery
	}
	*files = append(*files, value)
	*bytes += len(value)
	return nil
}

func ignoredRepositoryDirectory(name string) bool {
	return name == ".git" || name == "testdata" || name == "vendor" || strings.HasPrefix(name, "_") ||
		strings.HasPrefix(name, ".") && name != ".github"
}

func inspectRepositoryModule(
	ctx context.Context,
	root, directory string,
	tool Tool,
	runner repositoryModuleRunner,
) (RepositoryModule, error) {
	description, err := readModuleDescription(ctx, root, directory, tool, runner)
	if err != nil {
		return RepositoryModule{}, err
	}
	if len(description.Tool) != 0 && len(description.Replace) != 0 {
		return RepositoryModule{}, ErrRepositoryDiscovery
	}
	var tools []string
	if len(description.Tool) != 0 {
		tools = make([]string, len(description.Tool))
		for index, declared := range description.Tool {
			tools[index] = declared.Path
		}
		slices.Sort(tools)
	}
	return RepositoryModule{
		Directory: directory, Path: description.Module.Path, GoVersion: description.Go,
		Toolchain: description.Toolchain, Tools: tools,
	}, nil
}

func readModuleDescription(
	ctx context.Context,
	root, directory string,
	tool Tool,
	runner repositoryModuleRunner,
) (moduleDescription, error) {
	result, err := runRepositoryGo(ctx, root, directory, tool, runner, "mod", "edit", "-json")
	if err != nil {
		return moduleDescription{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	var description moduleDescription
	if err = decoder.Decode(&description); err != nil {
		return moduleDescription{}, errors.Join(ErrRepositoryDiscovery, err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return moduleDescription{}, errors.Join(ErrRepositoryDiscovery, err)
	}
	return description, nil
}

func classifyRepositoryPackages(ctx context.Context, modules []RepositoryModule, files []string) error {
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrRepositoryDiscovery, err)
		}
		owner := repositoryFileModule(modules, file)
		modules[owner].HasPackages = true
		modules[owner].HasProduction = modules[owner].HasProduction || !strings.HasSuffix(file, "_test.go")
	}
	return nil
}

func repositoryFileModule(modules []RepositoryModule, file string) int {
	owner := 0
	ownerBytes := 0
	for index, module := range modules[1:] {
		directory := strings.TrimSuffix(module.Directory, "/")
		if !strings.HasPrefix(file, directory+"/") {
			continue
		}
		if len(directory) > ownerBytes {
			owner = index + 1
			ownerBytes = len(directory)
		}
	}
	return owner
}

func runRepositoryGo(
	ctx context.Context,
	root, directory string,
	tool Tool,
	runner repositoryModuleRunner,
	arguments ...string,
) (proctree.Result, error) {
	return runRepositoryGoWithLimit(ctx, root, directory, tool, runner, MaxRepositoryCommandBytes, arguments...)
}

func runRepositoryGoWithLimit(
	ctx context.Context,
	root, directory string,
	tool Tool,
	runner repositoryModuleRunner,
	limit int,
	arguments ...string,
) (proctree.Result, error) {
	tool, err := admittedRepositoryGoOwner(ctx, root, directory, tool, runner)
	if err != nil {
		return proctree.Result{}, err
	}
	if limit <= 0 || limit > verify.MaxOutputBytes {
		return proctree.Result{}, ErrRepositoryDiscovery
	}
	outputLimit := min(tool.OutputLimit, limit)
	moduleRoot := root
	if directory != "." {
		moduleRoot = filepath.Join(root, filepath.FromSlash(directory))
	}
	commandArguments := append([]string{"-C", moduleRoot}, arguments...)
	result, runErr := runner(ctx, proctree.Command{
		Executable: tool.Executable, Arguments: commandArguments, Directory: root, Environment: tool.Environment,
		StdoutLimit: outputLimit, StderrLimit: outputLimit, Timeout: tool.Timeout,
	})
	if runErr != nil || !result.Started || result.ExitCode != 0 || result.Outcome != proctree.OutcomeCompleted {
		return proctree.Result{}, repositoryGoError(arguments, result, runErr)
	}
	if err := ctx.Err(); err != nil {
		return proctree.Result{}, errors.Join(ErrRepositoryDiscovery, err)
	}
	return result, nil
}

func admittedRepositoryGoOwner(ctx context.Context, root, directory string, tool Tool, runner repositoryModuleRunner) (Tool, error) {
	if ctx == nil || runner == nil {
		return Tool{}, fmt.Errorf("%w: missing Go command owner", ErrRepositoryDiscovery)
	}
	if !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes {
		return Tool{}, fmt.Errorf("%w: invalid Go command root", ErrRepositoryDiscovery)
	}
	if !validRepositoryGoDirectory(directory) {
		return Tool{}, fmt.Errorf("%w: invalid Go command directory", ErrRepositoryDiscovery)
	}
	rootInformation, err := os.Stat(root)
	if err != nil {
		return Tool{}, fmt.Errorf("%w: unavailable Go command root: %w", ErrRepositoryDiscovery, err)
	}
	if !rootInformation.IsDir() {
		return Tool{}, fmt.Errorf("%w: Go command root is not a directory", ErrRepositoryDiscovery)
	}
	if _, err = os.Stat(tool.Executable); err != nil {
		return Tool{}, fmt.Errorf("%w: unavailable Go executable: %w", ErrRepositoryDiscovery, err)
	}
	tool.Environment = append([]string(nil), tool.Environment...)
	control := verify.Control{ID: "go", Name: "Go", Command: verify.Command{
		Executable: tool.Executable, Environment: tool.Environment, Timeout: tool.Timeout, OutputLimit: tool.OutputLimit,
	}}
	plan := verify.Plan{ID: "go", Profiles: []verify.Profile{{ID: "go", Controls: []verify.Control{control}}}}
	if err := verify.Validate(root, plan); err != nil {
		return Tool{}, fmt.Errorf("%w: invalid Go tool owner: %w", ErrRepositoryDiscovery, err)
	}
	return tool, nil
}

func validRepositoryGoDirectory(directory string) bool {
	return len(directory) <= MaxFuzzPathBytes && (directory == "" || directory == "." || validRelativeDirectory(filepath.FromSlash(directory)))
}

func repositoryGoError(arguments []string, result proctree.Result, runErr error) error {
	commandErr := fmt.Errorf("go %s did not complete: exit %d", strings.Join(arguments, " "), result.ExitCode)
	diagnostic := strings.TrimSpace(string(diagnosticPrefix(result.Stderr)))
	if diagnostic != "" {
		commandErr = fmt.Errorf("%w: %s", commandErr, diagnostic)
	}
	return errors.Join(ErrRepositoryDiscovery, commandErr, runErr)
}

func validateRepositoryModules(modules []RepositoryModule) error {
	if len(modules) == 0 || len(modules) > MaxRepositoryModules || modules[0].Directory != "." {
		return ErrRepositoryDiscovery
	}
	toolchain := modules[0].Toolchain
	if !version.IsValid(toolchain) {
		return ErrRepositoryDiscovery
	}
	paths := make(map[string]bool, len(modules))
	directories := make(map[string]bool, len(modules))
	for index, module := range modules {
		if !validRepositoryModule(module, toolchain, index == 0, paths, directories) {
			return ErrRepositoryDiscovery
		}
		paths[module.Path] = true
		directories[module.Directory] = true
	}
	return nil
}

func validRepositoryModule(module RepositoryModule, toolchain string, root bool, paths, directories map[string]bool) bool {
	goVersion := "go" + module.GoVersion
	return validFuzzText(module.Path) && validFuzzText(module.Directory) && len(module.Path) <= MaxFuzzPathBytes && len(module.Directory) <= MaxFuzzPathBytes &&
		version.IsValid(goVersion) && validModuleToolchain(module.Toolchain, toolchain, root) &&
		version.Compare(goVersion, toolchain) <= 0 && !paths[module.Path] && !directories[module.Directory] &&
		validRelativeDirectory(filepath.FromSlash(module.Directory)) && validRepositoryTools(module.Tools)
}

func validModuleToolchain(candidate, root string, rootModule bool) bool {
	if rootModule {
		return candidate == root
	}
	return candidate == "" || candidate == "default" || version.IsValid(candidate)
}

func validRepositoryTools(tools []string) bool {
	if len(tools) > verify.MaxArguments {
		return false
	}
	for index, tool := range tools {
		if len(tool) > MaxFuzzPathBytes || !validFuzzText(tool) || tool[0] == '-' || index > 0 && tools[index-1] >= tool {
			return false
		}
	}
	return true
}

// RepositoryFromModules constructs repository ownership from a validated module inventory
func RepositoryFromModules(modules []RepositoryModule, base Repository) (Repository, error) {
	if !repositoryBaseAvailable(base) {
		return Repository{}, verify.ErrInvalidPlan
	}
	if err := validateRepositoryModules(modules); err != nil {
		return Repository{}, errors.Join(verify.ErrInvalidPlan, err)
	}
	base.ExactGo = modules[0].Toolchain
	base.Modules = make([]Module, len(modules))
	populateRepositoryModules(modules, &base)
	base.Compatibility = repositoryCompatibility(modules)
	return base, nil
}

func repositoryBaseAvailable(base Repository) bool {
	return base.ID != "" && base.Self != "" && base.LinterConfig != "" && len(base.Modules) == 0 &&
		len(base.TestScopes) == 0 && len(base.FuzzModules) == 0 && len(base.Compatibility) == 0
}

func populateRepositoryModules(modules []RepositoryModule, repository *Repository) {
	for index, module := range modules {
		directory := module.Directory
		if directory == "." {
			directory = ""
		}
		name := moduleDisplayName(module.Directory)
		repository.Modules[index] = Module{
			Directory: directory, Name: name, Tools: append([]string(nil), module.Tools...), Production: module.HasProduction,
		}
		if !module.HasPackages {
			continue
		}
		repository.Modules[index].Packages = []string{"./..."}
		repository.TestScopes = append(repository.TestScopes, TestScope{
			Directory: directory, Name: name, Packages: []string{"./..."}, SkipCoverage: !module.HasProduction,
		})
		repository.FuzzModules = append(repository.FuzzModules, FuzzModule{Directory: module.Directory, Path: module.Path})
	}
}

func moduleDisplayName(directory string) string {
	if directory == "." {
		return "Root"
	}
	return filepath.ToSlash(directory)
}

func repositoryCompatibility(modules []RepositoryModule) []Compatibility {
	minimum := ""
	for _, module := range modules {
		if !module.HasPackages {
			continue
		}
		candidate := "go" + module.GoVersion
		if minimum == "" || version.Compare(candidate, minimum) < 0 {
			minimum = candidate
		}
	}
	versions := goCompatibilityVersions(minimum, modules[0].Toolchain)
	result := make([]Compatibility, 0, len(versions))
	for _, candidate := range versions {
		names := make([]string, 0, len(modules))
		for _, module := range modules {
			if module.HasPackages && version.Compare("go"+module.GoVersion, candidate) <= 0 {
				names = append(names, moduleDisplayName(module.Directory))
			}
		}
		slices.Sort(names)
		result = append(result, Compatibility{Version: candidate, Scopes: names})
	}
	return result
}

func goCompatibilityVersions(minimum, maximum string) []string {
	minimumParts, minimumOK := goVersionParts(minimum)
	maximumParts, maximumOK := goVersionParts(maximum)
	if !minimumOK || !maximumOK || minimumParts[0] != maximumParts[0] || minimumParts[1] > maximumParts[1] {
		return nil
	}
	if minimum == maximum {
		return nil
	}
	result := make([]string, 0, maximumParts[1]-minimumParts[1])
	for minor := minimumParts[1]; minor < maximumParts[1]; minor++ {
		candidate := fmt.Sprintf("go%d.%d.0", minimumParts[0], minor)
		if minor == minimumParts[1] && minimumParts[2] != 0 {
			candidate = minimum
		}
		result = append(result, candidate)
	}
	if len(result) == 0 {
		result = append(result, minimum)
	}
	return result
}

func goVersionParts(value string) ([goVersionComponents]int, bool) {
	var result [goVersionComponents]int
	if !version.IsValid(value) {
		return result, false
	}
	components := strings.Split(strings.TrimPrefix(value, "go"), ".")
	for index, component := range components {
		parsed, err := strconv.Atoi(component)
		if err != nil || parsed < 0 {
			return [goVersionComponents]int{}, false
		}
		result[index] = parsed
	}
	return result, true
}

// ResolveRepositoryTool resolves one uniquely declared Go tool executable
func ResolveRepositoryTool(ctx context.Context, root string, modules []RepositoryModule, modulePath string, tool Tool) (string, error) {
	return resolveRepositoryTool(ctx, root, modules, modulePath, tool, proctree.Run)
}

func resolveRepositoryTool(
	ctx context.Context,
	root string,
	modules []RepositoryModule,
	modulePath string,
	tool Tool,
	runner repositoryModuleRunner,
) (string, error) {
	if !validFuzzText(modulePath) || len(modulePath) > MaxFuzzPathBytes {
		return "", ErrRepositoryDiscovery
	}
	directory, err := repositoryToolDirectory(modules, modulePath)
	if err != nil {
		return "", err
	}
	name := path.Base(modulePath)
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOFLAGS", "-mod=readonly")
	result, err := runRepositoryGo(ctx, root, directory, tool, runner, "tool", "-n", name)
	if err != nil {
		return "", err
	}
	executable := strings.TrimSuffix(string(result.Stdout), "\n")
	executable = strings.TrimSuffix(executable, "\r")
	if executable == "" || !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\r\n") {
		return "", ErrRepositoryDiscovery
	}
	return executable, nil
}

func repositoryToolDirectory(modules []RepositoryModule, modulePath string) (string, error) {
	directory := ""
	found := false
	for _, module := range modules {
		for _, declared := range module.Tools {
			if declared != modulePath {
				continue
			}
			if found {
				return "", ErrRepositoryDiscovery
			}
			if !validRelativeDirectory(filepath.FromSlash(module.Directory)) {
				return "", ErrRepositoryDiscovery
			}
			directory = module.Directory
			found = true
		}
	}
	if !found {
		return "", ErrRepositoryDiscovery
	}
	return directory, nil
}
