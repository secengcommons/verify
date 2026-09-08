package goverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/secengcommons/proctree"
)

const MaxFuzzModules = 16
const MaxFuzzEntries = 100_000
const MaxFuzzSourceBytes = maxSourceBytes
const MaxFuzzTotalBytes = 64 << 20
const MaxFuzzPathBytes = 4 << 10
const MaxFuzzJobs = 32
const MaxFuzzDiagnosticBytes = 4 << 10

var ErrFuzzInventory = errors.New("invalid Go fuzz inventory")

// FuzzModule binds one module path to its repository directory
type FuzzModule struct {
	Directory string // Directory is repository-relative; dot selects the root
	Path      string // Path is the declared module path
}

// TestTarget identifies one source-declared fuzz target or benchmark candidate
type TestTarget struct {
	Module    string // Module is the owning module path
	Package   string // Package is the complete package import path
	Name      string // Name is the source declaration name
	Directory string // Directory is the owning module directory
	Argument  string // Argument is the package argument relative to Directory
}

// FuzzTarget identifies one fuzz candidate whose signature remains compiler-owned
type FuzzTarget = TestTarget

// BenchmarkTarget identifies one benchmark candidate whose signature remains compiler-owned
type BenchmarkTarget = TestTarget

// TestTargets contains the complete ordered source target inventory
type TestTargets struct {
	Fuzz       []FuzzTarget      // Fuzz contains source-declared fuzz candidates
	Benchmarks []BenchmarkTarget // Benchmarks contains source-declared benchmark candidates
}

type inventory struct {
	root                string
	opened              *os.Root
	entries             int
	bytes               int
	targets             []FuzzTarget
	identities          map[string]bool
	benchmarks          []BenchmarkTarget
	benchmarkIdentities map[string]bool
	tool                Tool
	run                 repositoryModuleRunner
	active              map[string]bool
}

// DiscoverFuzzTargets inventories source candidates without executing repository code
func DiscoverFuzzTargets(ctx context.Context, root string, tool Tool, modules []FuzzModule) (targets []FuzzTarget, err error) {
	result, err := DiscoverTestTargets(ctx, root, tool, modules)
	return result.Fuzz, err
}

// DiscoverTestTargets inventories fuzz and benchmark source candidates
func DiscoverTestTargets(ctx context.Context, root string, tool Tool, modules []FuzzModule) (targets TestTargets, err error) {
	return discoverTestTargetsWith(ctx, root, tool, modules, proctree.Run)
}

func discoverTestTargetsWith(ctx context.Context, root string, tool Tool, modules []FuzzModule, run repositoryModuleRunner) (targets TestTargets, err error) {
	if ctx == nil {
		return TestTargets{}, ErrFuzzInventory
	}
	if err := ctx.Err(); err != nil {
		return TestTargets{}, errors.Join(ErrFuzzInventory, err)
	}
	if err := validInventoryRequest(root, modules); err != nil {
		return TestTargets{}, err
	}
	root, err = canonicalFuzzRoot(root)
	if err != nil {
		return TestTargets{}, err
	}
	opened, err := openFuzzRoot(root)
	if err != nil {
		return TestTargets{}, err
	}
	defer func() { err = errors.Join(err, opened.Close()) }()
	owner := inventory{
		root: root, opened: opened, targets: make([]FuzzTarget, 0), identities: make(map[string]bool),
		benchmarks: make([]BenchmarkTarget, 0), benchmarkIdentities: make(map[string]bool),
		tool: tool, run: run,
	}
	for _, module := range modules {
		owner.active, err = owner.activeTestFiles(ctx, module)
		if err != nil {
			return TestTargets{}, err
		}
		if err = owner.walkModule(ctx, module); err != nil {
			return TestTargets{}, err
		}
		if len(owner.active) != 0 {
			return TestTargets{}, ErrFuzzInventory
		}
	}
	if err = ctx.Err(); err != nil {
		return TestTargets{}, errors.Join(ErrFuzzInventory, err)
	}
	slices.SortFunc(owner.targets, compareTarget)
	slices.SortFunc(owner.benchmarks, compareTarget)
	return TestTargets{Fuzz: owner.targets, Benchmarks: owner.benchmarks}, nil
}

func canonicalFuzzRoot(root string) (string, error) {
	return canonicalFuzzRootWith(root, filepath.EvalSymlinks)
}

func canonicalFuzzRootWith(root string, evaluate func(string) (string, error)) (string, error) {
	resolved, err := evaluate(root)
	if err != nil {
		return "", errors.Join(ErrFuzzInventory, err)
	}
	return resolved, nil
}

func openFuzzRoot(root string) (*os.Root, error) {
	return openFuzzRootWith(root, os.OpenRoot)
}

func openFuzzRootWith(root string, open func(string) (*os.Root, error)) (*os.Root, error) {
	opened, err := open(root)
	if err != nil {
		return nil, errors.Join(ErrFuzzInventory, err)
	}
	return opened, nil
}

func validInventoryRequest(root string, modules []FuzzModule) error {
	if !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes || len(modules) == 0 || len(modules) > MaxFuzzModules {
		return ErrFuzzInventory
	}
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		directory := filepath.FromSlash(module.Directory)
		if !validFuzzText(module.Path) || len(module.Path) > MaxFuzzPathBytes || !validFuzzText(module.Directory) ||
			!validRelativeDirectory(directory) || seen[directory] {
			return ErrFuzzInventory
		}
		seen[directory] = true
	}
	return nil
}

func validFuzzText(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	for _, character := range value {
		if !strconv.IsPrint(character) {
			return false
		}
	}
	return true
}

func validRelativeDirectory(directory string) bool {
	return directory == "." || directory != "" && !filepath.IsAbs(directory) && directory == filepath.Clean(directory) &&
		directory != ".." && !strings.HasPrefix(directory, ".."+string(filepath.Separator))
}

func (owner *inventory) walkModule(ctx context.Context, module FuzzModule) error {
	directory := filepath.FromSlash(module.Directory)
	return owner.walkDirectory(ctx, module, directory, ".")
}

func (owner *inventory) walkDirectory(ctx context.Context, module FuzzModule, directory, relative string) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrFuzzInventory, err)
	}
	entries, err := owner.readDirectory(ctx, directory)
	if err != nil {
		return err
	}
	if relative != "." && containsGoModule(entries) {
		return nil
	}
	for _, entry := range entries {
		if err = owner.walkEntry(ctx, module, directory, relative, entry); err != nil {
			return err
		}
	}
	return nil
}

func (owner *inventory) walkEntry(ctx context.Context, module FuzzModule, directory, relative string, entry os.DirEntry) error {
	if entry.Type()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic link %s", ErrFuzzInventory, filepath.Join(directory, entry.Name()))
	}
	childRelative := entry.Name()
	if relative != "." {
		childRelative = filepath.Join(relative, entry.Name())
	}
	child := filepath.Join(directory, entry.Name())
	if entry.IsDir() {
		if ignoredGoDirectory(entry.Name()) {
			return nil
		}
		return owner.walkDirectory(ctx, module, child, childRelative)
	}
	if !entry.Type().IsRegular() {
		return fmt.Errorf("%w: unsupported file %s", ErrFuzzInventory, filepath.Join(directory, entry.Name()))
	}
	if strings.HasSuffix(entry.Name(), "_test.go") {
		return owner.inspectFile(ctx, module, directory, childRelative)
	}
	return nil
}

func (owner *inventory) readDirectory(ctx context.Context, directory string) ([]os.DirEntry, error) {
	opened, err := owner.opened.Open(directory)
	if err != nil {
		return nil, errors.Join(ErrFuzzInventory, err)
	}
	remaining := MaxFuzzEntries - owner.entries
	entries, readErr := readBoundedDirectory(ctx, opened.ReadDir, opened.Close, remaining, ErrFuzzInventory)
	owner.entries += len(entries)
	return entries, readErr
}

func containsGoModule(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if entry.Name() == "go.mod" && entry.Type().IsRegular() {
			return true
		}
	}
	return false
}

func ignoredGoDirectory(name string) bool {
	return name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

func (owner *inventory) inspectFile(ctx context.Context, module FuzzModule, directory, relative string) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrFuzzInventory, err)
	}
	name := filepath.Join(directory, filepath.Base(relative))
	if !owner.active[name] {
		return nil
	}
	delete(owner.active, name)
	source, err := owner.readSource(name)
	if err != nil {
		return err
	}
	fuzz, benchmarks, err := testTargetNames(relative, source)
	if err != nil {
		return err
	}
	return owner.collectFileTargets(module, relative, fuzz, benchmarks)
}

type listedTestPackage struct {
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
}

func (owner *inventory) activeTestFiles(ctx context.Context, module FuzzModule) (map[string]bool, error) {
	result, err := runRepositoryGoWithLimit(ctx, owner.root, module.Directory, owner.tool, owner.run, owner.tool.OutputLimit,
		"list", "-json=Dir,TestGoFiles,XTestGoFiles", "./...")
	if err != nil {
		return nil, errors.Join(ErrFuzzInventory, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	active := make(map[string]bool)
	packages := 0
	for {
		var listed listedTestPackage
		if err = decoder.Decode(&listed); errors.Is(err, io.EOF) {
			break
		}
		packages++
		if err != nil || packages > MaxFuzzEntries {
			return nil, errors.Join(ErrFuzzInventory, err)
		}
		if err = owner.addListedTestFiles(active, module, listed); err != nil {
			return nil, err
		}
	}
	return active, nil
}

func (owner *inventory) addListedTestFiles(active map[string]bool, module FuzzModule, listed listedTestPackage) error {
	if !filepath.IsAbs(listed.Dir) {
		return ErrFuzzInventory
	}
	directory, err := filepath.Rel(owner.root, listed.Dir)
	if err != nil || !validRelativeDirectory(directory) || !withinModule(directory, filepath.FromSlash(module.Directory)) {
		return errors.Join(ErrFuzzInventory, err)
	}
	if err = addListedFiles(active, directory, listed.TestGoFiles); err != nil {
		return err
	}
	return addListedFiles(active, directory, listed.XTestGoFiles)
}

func addListedFiles(active map[string]bool, directory string, files []string) error {
	for _, file := range files {
		if filepath.Base(file) != file || !strings.HasSuffix(file, "_test.go") {
			return ErrFuzzInventory
		}
		name := filepath.Join(directory, file)
		if len(active) == MaxFuzzEntries || active[name] {
			return ErrFuzzInventory
		}
		active[name] = true
	}
	return nil
}

func withinModule(directory, module string) bool {
	if module == "." {
		return true
	}
	return directory == module || strings.HasPrefix(directory, module+string(filepath.Separator))
}

func fuzzNames(name string, source []byte) ([]string, error) {
	fuzz, _, err := testTargetNames(name, source)
	return fuzz, err
}

func testTargetNames(name string, source []byte) ([]string, []string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, errors.Join(ErrFuzzInventory, err)
	}
	fuzz := make([]string, 0)
	benchmarks := make([]string, 0)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fuzzFunction(function) {
			fuzz = append(fuzz, function.Name.Name)
		}
		if benchmarkFunction(function) {
			benchmarks = append(benchmarks, function.Name.Name)
		}
	}
	return fuzz, benchmarks, nil
}

func (owner *inventory) collectFileTargets(module FuzzModule, relative string, fuzz, benchmarks []string) error {
	packageRelative := filepath.Dir(relative)
	if packageRelative == "." {
		packageRelative = ""
	}
	for _, name := range fuzz {
		if err := owner.addTarget(module, packageRelative, name); err != nil {
			return err
		}
	}
	for _, name := range benchmarks {
		if err := owner.addBenchmark(module, packageRelative, name); err != nil {
			return err
		}
	}
	return nil
}

func (owner *inventory) addTarget(module FuzzModule, packageRelative, name string) error {
	return addTestTarget(&owner.targets, owner.identities, module, packageRelative, name)
}

func (owner *inventory) addBenchmark(module FuzzModule, packageRelative, name string) error {
	return addTestTarget(&owner.benchmarks, owner.benchmarkIdentities, module, packageRelative, name)
}

func addTestTarget(targets *[]TestTarget, identities map[string]bool, module FuzzModule, packageRelative, name string) error {
	if len(*targets) == MaxFuzzTargets {
		return ErrFuzzInventory
	}
	packageName, argument := targetPackage(module, packageRelative)
	identity := packageName + "/" + name
	if identities[identity] {
		return fmt.Errorf("%w: duplicate target %s", ErrFuzzInventory, identity)
	}
	identities[identity] = true
	*targets = append(*targets, TestTarget{
		Module: module.Path, Package: packageName, Name: name,
		Directory: module.Directory, Argument: argument,
	})
	return nil
}

func targetPackage(module FuzzModule, packageRelative string) (string, string) {
	if packageRelative == "" {
		return module.Path, "."
	}
	return path.Join(module.Path, filepath.ToSlash(packageRelative)), "./" + filepath.ToSlash(packageRelative)
}

func (owner *inventory) readSource(name string) ([]byte, error) {
	opened, err := owner.opened.Open(name)
	if err != nil {
		return nil, errors.Join(ErrFuzzInventory, err)
	}
	source, err := readSourceFile(boundedSource{
		reader: opened,
		stat:   opened.Stat,
		close:  opened.Close,
	})
	if err != nil {
		return nil, err
	}
	owner.bytes += len(source)
	if owner.bytes > MaxFuzzTotalBytes {
		return nil, ErrFuzzInventory
	}
	return source, nil
}

func readSourceFile(source boundedSource) ([]byte, error) {
	return readBoundedSource(source, ErrFuzzInventory)
}

func fuzzFunction(function *ast.FuncDecl) bool {
	if !validTestTargetDeclaration(function, fuzzName) {
		return false
	}
	return testTargetParameter(function.Type.Params.List[0])
}

func validTestTargetDeclaration(function *ast.FuncDecl, validName func(string) bool) bool {
	return function.Recv == nil && function.Type.TypeParams == nil && (function.Type.Results == nil || len(function.Type.Results.List) == 0) &&
		validName(function.Name.Name) && function.Type.Params != nil && len(function.Type.Params.List) == 1
}

func testTargetParameter(parameter *ast.Field) bool {
	_, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if len(parameter.Names) > 1 {
		return false
	}
	return len(parameter.Names) <= 1
}

func benchmarkFunction(function *ast.FuncDecl) bool {
	return validTestTargetDeclaration(function, benchmarkName) &&
		testTargetParameter(function.Type.Params.List[0])
}

func fuzzName(name string) bool {
	return testTargetName(name, "Fuzz")
}

func benchmarkName(name string) bool {
	return testTargetName(name, "Benchmark")
}

func testTargetName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	remainder := strings.TrimPrefix(name, prefix)
	if remainder == "" {
		return true
	}
	first, _ := utf8.DecodeRuneInString(remainder)
	return !unicode.IsLower(first)
}

func compareTarget(left, right FuzzTarget) int {
	if compared := strings.Compare(left.Module, right.Module); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Package, right.Package); compared != 0 {
		return compared
	}
	return strings.Compare(left.Name, right.Name)
}
