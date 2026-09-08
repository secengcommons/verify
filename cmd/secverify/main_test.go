package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	commandline "github.com/secengcommons/cli"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

func TestMain(testingMain *testing.M) {
	if handled, code := verify.DispatchProcessOwner(os.Args); handled {
		os.Exit(code)
	}
	os.Exit(testingMain.Run())
}

func TestRunHelpAndVersion(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, argument := range []string{"help", "--version"} {
		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{"secverify", argument}, &stdout, &stderr)
		if code != exitPass || stderr.Len() != 0 || stdout.Len() == 0 {
			t.Fatalf("run %s = (%d, %q, %q) from %s", argument, code, stdout.String(), stderr.String(), root)
		}
	}
}

func TestCommandHelpDescribesRootedInvocation(t *testing.T) {
	parser, err := commandParser()
	if err != nil {
		t.Fatal(err)
	}
	help, err := parser.Help("")
	if err != nil || !strings.HasPrefix(string(help), "Usage:\n") || !strings.Contains(string(help), "Available Commands:\n") ||
		!strings.Contains(string(help), "-r, --root PATH") || !strings.Contains(string(help), "static") {
		t.Fatalf("command help = (%q, %v)", help, err)
	}
	help, err = parser.Help("static")
	if err != nil || !strings.HasPrefix(string(help), "Usage:\n  secverify static [flags]\n") {
		t.Fatalf("static help = (%q, %v)", help, err)
	}
}

func TestCommandDefinitionCoversEveryProfile(t *testing.T) {
	definition := commandDefinition()
	want := []string{"static", "compatibility", "test", "campaign", "fuzz-inventory", "benchmark", "all"}
	if len(definition.Commands) != len(want) {
		t.Fatalf("commands = %d, want %d", len(definition.Commands), len(want))
	}
	for index, name := range want {
		if definition.Commands[index].Name != name || definition.Commands[index].Summary == "" {
			t.Fatalf("command %d = %#v, want %q", index, definition.Commands[index], name)
		}
	}
}

func TestCommandOutputFailures(t *testing.T) {
	parser, err := commandParser()
	if err != nil {
		t.Fatal(err)
	}
	if code := writeCommandHelp(commandline.Parser{}, io.Discard, ""); code != exitInvocation {
		t.Fatalf("invalid help exit = %d", code)
	}
	if code := writeCommandHelp(parser, errorWriter{}, ""); code != exitInvocation {
		t.Fatalf("help writer exit = %d", code)
	}
	if code := writeCommandDiagnostic(commandline.Parser{}, io.Discard, commandline.ErrInvocation); code != exitInvocation {
		t.Fatalf("invalid diagnostic exit = %d", code)
	}
	if code := writeCommandDiagnostic(parser, errorWriter{}, commandline.ErrInvocation); code != exitInvocation {
		t.Fatalf("diagnostic writer exit = %d", code)
	}
	if code := runCommandInvocation(t.Context(), commandline.Invocation{}, commandline.Parser{}, executableIdentity{}, io.Discard, io.Discard, nil, nil); code != exitInvocation {
		t.Fatalf("invalid action exit = %d", code)
	}
	invocation, err := parser.Parse([]string{"--version"})
	if err != nil {
		t.Fatal(err)
	}
	if code := runCommandInvocation(t.Context(), invocation, parser, validIdentityFixture(), errorWriter{}, io.Discard, nil, nil); code != exitInvocation {
		t.Fatalf("version writer exit = %d", code)
	}
}

func TestExecutableVersionRequiresReleasedDependencies(t *testing.T) {
	information := releasedBuildInfo()
	if version := executableVersion(information, true); version != "0.1.0" {
		t.Fatalf("version = %q", version)
	}
}

func TestExecutableVersionRejectsUnreleasedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*debug.BuildInfo)
	}{
		{name: "wrong module", mutate: func(value *debug.BuildInfo) { value.Main.Path = "example.test/verify" }},
		{name: "replaced main", mutate: func(value *debug.BuildInfo) {
			value.Main.Replace = &debug.Module{Path: "../verify", Version: "(devel)"}
		}},
		{name: "development main", mutate: func(value *debug.BuildInfo) { value.Main.Version = "(devel)" }},
		{name: "missing CLI", mutate: func(value *debug.BuildInfo) { value.Deps = value.Deps[1:] }},
		{name: "missing Proctree", mutate: func(value *debug.BuildInfo) { value.Deps = append(value.Deps[:1], value.Deps[2:]...) }},
		{name: "missing YAML", mutate: func(value *debug.BuildInfo) { value.Deps = value.Deps[:2] }},
		{name: "wrong CLI version", mutate: func(value *debug.BuildInfo) { value.Deps[0].Version = "v1.0.1" }},
		{name: "wrong Proctree version", mutate: func(value *debug.BuildInfo) { value.Deps[1].Version = "v1.0.1" }},
		{name: "wrong YAML version", mutate: func(value *debug.BuildInfo) { value.Deps[2].Version = "v3.0.4" }},
		{name: "replaced dependency", mutate: func(value *debug.BuildInfo) {
			value.Deps[0].Replace = &debug.Module{Path: "../cli", Version: "(devel)"}
		}},
		{name: "duplicate dependency", mutate: func(value *debug.BuildInfo) { value.Deps = append(value.Deps, qualifiedCLI()) }},
		{name: "unrelated replacement", mutate: func(value *debug.BuildInfo) {
			value.Deps = append(value.Deps, &debug.Module{Path: "example.test/dependency", Version: "v1.0.0", Replace: &debug.Module{Path: "../dependency", Version: "(devel)"}})
		}},
	}
	if version := executableVersion(nil, false); version != developmentVersion {
		t.Fatalf("unavailable version = %q", version)
	}
	if version := executableVersion(nil, true); version != developmentVersion {
		t.Fatalf("missing information version = %q", version)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			information := releasedBuildInfo()
			test.mutate(information)
			if version := executableVersion(information, true); version != developmentVersion {
				t.Fatalf("version = %q", version)
			}
		})
	}
}

func releasedBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		Main: debug.Module{Path: verifyModule, Version: "v0.1.0"},
		Deps: []*debug.Module{qualifiedCLI(), qualifiedProctree(), qualifiedYAML()},
	}
}

func qualifiedCLI() *debug.Module {
	return &debug.Module{Path: cliModule, Version: qualifiedCLIVersion}
}

func qualifiedProctree() *debug.Module {
	return &debug.Module{Path: proctreeModule, Version: qualifiedProctreeVersion}
}

func qualifiedYAML() *debug.Module {
	return &debug.Module{Path: yamlModule, Version: qualifiedYAMLVersion}
}

func TestBuildUsesQualifiedDependencies(t *testing.T) {
	information, available := debug.ReadBuildInfo()
	if !available || information == nil {
		t.Fatal("build information is unavailable")
	}
	required := map[string]string{cliModule: qualifiedCLIVersion, proctreeModule: qualifiedProctreeVersion, yamlModule: qualifiedYAMLVersion}
	found := make(map[string]bool, len(required))
	for _, dependency := range information.Deps {
		recordQualifiedDependency(t, dependency, required, found)
	}
	if len(found) != len(required) {
		t.Fatalf("qualified dependencies = %v", found)
	}
}

func recordQualifiedDependency(t *testing.T, dependency *debug.Module, required map[string]string, found map[string]bool) {
	t.Helper()
	if dependency == nil {
		return
	}
	if dependency.Replace != nil {
		t.Fatalf("replaced dependency = %#v", dependency)
	}
	version, qualified := required[dependency.Path]
	if !qualified {
		return
	}
	if found[dependency.Path] {
		t.Fatalf("duplicate dependency = %#v", dependency)
	}
	if dependency.Version != version {
		t.Fatalf("dependency = %#v", dependency)
	}
	found[dependency.Path] = true
}

func TestReleasedVersion(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{version: "v1.0.0", valid: true},
		{version: "v0.1.0", valid: true},
		{version: ""},
		{version: "1.0.0"},
		{version: "v1.0"},
		{version: "v1..0"},
		{version: "v01.0.0"},
		{version: "v1.a.0"},
		{version: "v0.0.0"},
		{version: "v1.0.0-rc.1"},
	}
	for _, test := range tests {
		if actual := releasedVersion(test.version); actual != test.valid {
			t.Errorf("releasedVersion(%q) = %t", test.version, actual)
		}
	}
}

func TestRunRejectsInvalidInvocationAndPlan(t *testing.T) {
	if code := run(t.Context(), nil, io.Discard, io.Discard); code != exitInvocation {
		t.Fatalf("empty invocation exit = %d", code)
	}
	if code := run(nilContext(), []string{"secverify", "__go-coverage-self-test"}, io.Discard, io.Discard); code != exitInvocation {
		t.Fatalf("nil context exit = %d", code)
	}
	if code := runWith(t.Context(), []string{"secverify", "help"}, nil, io.Discard, os.Getwd, repositoryPlan); code != exitInvocation {
		t.Fatalf("nil writer exit = %d", code)
	}
	if code := runWith(t.Context(), []string{"secverify", "help"}, errorWriter{}, io.Discard, os.Getwd, repositoryPlan); code != exitInvocation {
		t.Fatalf("help writer exit = %d", code)
	}
	checkRepositoryInvocationFailures(t)
	parserFailure := errors.New("parser")
	if code := runWithParser(t.Context(), []string{"secverify", "help"}, io.Discard, io.Discard, os.Getwd, repositoryPlan,
		func() (commandline.Parser, error) { return commandline.Parser{}, parserFailure }); code != exitInvocation {
		t.Fatalf("parser failure exit = %d", code)
	}
	var stdout, stderr bytes.Buffer
	if code := runWith(t.Context(), []string{"secverify", "static"}, &stdout, &stderr,
		func() (string, error) { return t.TempDir(), nil }, func(context.Context, string, string) (verify.Plan, error) {
			return verify.Plan{}, verify.ErrInvalidPlan
		}); code != exitInvocation || !strings.HasPrefix(stdout.String(), "secverify source=") || stderr.Len() == 0 {
		t.Fatalf("invalid plan = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
}

func checkRepositoryInvocationFailures(t *testing.T) {
	t.Helper()
	if code := runRepositoryInvocation(nilContext(), commandInvocation{}, validIdentityFixture(), io.Discard, io.Discard, os.Getwd, repositoryPlan); code != exitInvocation {
		t.Fatalf("nil repository context exit = %d", code)
	}
	if code := runRepositoryInvocation(t.Context(), commandInvocation{}, validIdentityFixture(), io.Discard, nil, os.Getwd, repositoryPlan); code != exitInvocation {
		t.Fatalf("nil repository diagnostic exit = %d", code)
	}
	var identityError bytes.Buffer
	if code := runRepositoryInvocation(t.Context(), commandInvocation{}, validIdentityFixture(), errorWriter{}, &identityError, os.Getwd, repositoryPlan); code != exitInvocation || identityError.Len() == 0 {
		t.Fatalf("repository identity failure = (%d, %q)", code, identityError.String())
	}
}

func TestRunChecksCancellationBeforeCommandWork(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	var stderr bytes.Buffer
	code := runWithParser(cancelled, []string{"secverify", "help"}, io.Discard, &stderr,
		func() (string, error) { called = true; return "", nil },
		func(context.Context, string, string) (verify.Plan, error) { called = true; return verify.Plan{}, nil },
		func() (commandline.Parser, error) { called = true; return commandline.Parser{}, nil })
	if code != exitCancelled || called || !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("cancelled command = (%d, %t, %q)", code, called, stderr.String())
	}
}

func nilContext() context.Context { return nil }

func TestRunWithExecutesSelectedProfile(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plan := verify.Plan{ID: "plan", Profiles: []verify.Profile{{ID: "test", Controls: []verify.Control{{
		ID: "command", Name: "Command", Command: verify.Command{
			Executable: executable, Arguments: []string{"-test.run=^$"}, Environment: selectedEnvironment(),
			Timeout: controlTimeout, OutputLimit: verify.MaxOutputBytes,
		},
	}}}}}
	build := func(context.Context, string, string) (verify.Plan, error) { return plan, nil }
	var stdout, stderr bytes.Buffer
	code := runWith(t.Context(), []string{"secverify", "test"}, &stdout, &stderr,
		func() (string, error) { return t.TempDir(), nil }, build)
	if code != exitPass || stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("profile = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
}

func TestRunWithUsesExplicitRepositoryRoot(t *testing.T) {
	parent := t.TempDir()
	working := filepath.Join(parent, "tools")
	if err := os.Mkdir(working, 0o700); err != nil {
		t.Fatal(err)
	}
	want, err := canonicalRepositoryRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	observedRoot, observedProfile := "", ""
	failure := errors.New("stop after root selection")
	build := func(_ context.Context, root, profile string) (verify.Plan, error) {
		observedRoot, observedProfile = root, profile
		return verify.Plan{}, failure
	}
	var stderr bytes.Buffer
	code := runWith(t.Context(), []string{"secverify", "--root", "..", "static"}, io.Discard, &stderr,
		func() (string, error) { return working, nil }, build)
	if code != exitFail || observedRoot != want || observedProfile != "static" || !strings.Contains(stderr.String(), failure.Error()) {
		t.Fatalf("explicit root = (%d, %q, %q, %q)", code, observedRoot, observedProfile, stderr.String())
	}
}

func TestRunWithAcceptsStandardRootFlagForms(t *testing.T) {
	parent := t.TempDir()
	working := filepath.Join(parent, "tools")
	if err := os.Mkdir(working, 0o700); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("stop after parsing")
	want, err := canonicalRepositoryRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"secverify", "--root=..", "static"},
		{"secverify", "-r", "..", "static"},
		{"secverify", "static", "--root", ".."},
		{"secverify", "static", "-root", ".."},
	} {
		observedRoot, observedProfile := "", ""
		build := func(_ context.Context, root, profile string) (verify.Plan, error) {
			observedRoot, observedProfile = root, profile
			return verify.Plan{}, failure
		}
		code := runWith(t.Context(), arguments, io.Discard, io.Discard, func() (string, error) { return working, nil }, build)
		if code != exitFail || observedRoot != want || observedProfile != "static" {
			t.Fatalf("arguments %q = (%d, %q, %q)", arguments, code, observedRoot, observedProfile)
		}
	}
}

func TestRunWithRejectsUnknownCommandBeforeRepositoryWork(t *testing.T) {
	var stderr bytes.Buffer
	code := runWith(t.Context(), []string{"secverify", "unknown"}, io.Discard, &stderr,
		func() (string, error) { t.Fatal("unknown command resolved the repository"); return "", nil }, nil)
	if code != exitInvocation || !strings.Contains(stderr.String(), `Error: unknown command "unknown" for "secverify"`) {
		t.Fatalf("unknown command = (%d, %q)", code, stderr.String())
	}
}

func TestRunWithCobraStyleDiagnostics(t *testing.T) {
	for _, arguments := range [][]string{{"secverify"}, {"secverify", "-h"}, {"secverify", "help"}, {"secverify", "help", "static"}} {
		var stdout bytes.Buffer
		code := runWith(t.Context(), arguments, &stdout, io.Discard,
			func() (string, error) { t.Fatal("help resolved the repository"); return "", nil }, nil)
		if code != exitPass || !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("help %q = (%d, %q)", arguments, code, stdout.String())
		}
	}
	for _, arguments := range [][]string{
		{"secverify", "v"}, {"secverify", "version"}, {"secverify", "-v"}, {"secverify", "--v"}, {"secverify", "--version"},
	} {
		var stdout bytes.Buffer
		code := runWith(t.Context(), arguments, &stdout, io.Discard,
			func() (string, error) { t.Fatal("version resolved the repository"); return "", nil }, nil)
		if code != exitPass || !strings.HasPrefix(stdout.String(), "secverify ") {
			t.Fatalf("version %q = (%d, %q)", arguments, code, stdout.String())
		}
	}
}

func TestRunWithRejectsInvalidExplicitRootInvocation(t *testing.T) {
	for _, arguments := range [][]string{
		{"secverify", "--root"},
		{"secverify", "--root="},
		{"secverify", "--root", ".", "static", "extra"},
	} {
		if code := runWith(t.Context(), arguments, io.Discard, io.Discard, os.Getwd, nil); code != exitInvocation {
			t.Fatalf("arguments %#v exit = %d", arguments, code)
		}
	}
}

func TestRepositoryRootSelection(t *testing.T) {
	root := t.TempDir()
	canonical, err := canonicalRepositoryRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := resolveRepositoryRoot(root, ""); err != nil || selected != canonical {
		t.Fatalf("current root = (%q, %v)", selected, err)
	}
	if selected, err := resolveRepositoryRoot(t.TempDir(), root); err != nil || selected != canonical {
		t.Fatalf("absolute root = (%q, %v)", selected, err)
	}
	if _, err := resolveRepositoryRoot("relative", ""); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("relative working directory error = %v", err)
	}
	if _, err := resolveRepositoryRoot(root, "missing"); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("missing root error = %v", err)
	}
}

func TestRepositoryPlanThroughLinkedRoot(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	linked := filepath.Join(t.TempDir(), "repository & selected")
	createRepositoryLink(t, root, linked)
	selected, err := resolveRepositoryRoot(root, linked)
	if err != nil {
		t.Fatalf("resolve linked repository: %v", err)
	}
	if _, err = repositoryPlan(t.Context(), selected, "fuzz-inventory"); err != nil {
		t.Fatalf("build linked repository plan: %v", err)
	}
}

func TestRunWithRejectsDirectoryFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("directory")
	code := runWith(t.Context(), []string{"secverify", "static"}, io.Discard, io.Discard,
		func() (string, error) { return "", failure }, nil)
	if code != exitFail {
		t.Fatalf("directory failure exit = %d", code)
	}
	code = runWith(t.Context(), []string{"secverify", "static"}, io.Discard, io.Discard,
		func() (string, error) { return "relative", nil }, nil)
	if code != exitInvocation {
		t.Fatalf("relative directory exit = %d", code)
	}
	code = runWith(t.Context(), []string{"secverify", "static"}, io.Discard, io.Discard,
		func() (string, error) { return t.TempDir(), nil },
		func(context.Context, string, string) (verify.Plan, error) { return verify.Plan{}, failure })
	if code != exitFail {
		t.Fatalf("plan failure exit = %d", code)
	}
}

func TestRunWithDiagnosticsDoNotResolveDirectory(t *testing.T) {
	t.Parallel()
	for _, argument := range []string{"help", "--help", "--version"} {
		var stdout bytes.Buffer
		code := runWith(t.Context(), []string{"secverify", argument}, &stdout, io.Discard,
			func() (string, error) { t.Fatal("diagnostic resolved current directory"); return "", nil }, nil)
		if code != exitPass || stdout.Len() == 0 {
			t.Fatalf("%s = (%d, %q)", argument, code, stdout.String())
		}
	}
}

func TestMainUsesExitResult(t *testing.T) {
	originalExit := exitProcess
	originalArguments := os.Args
	originalOutput, originalError := standardOutput, standardError
	t.Cleanup(func() {
		exitProcess = originalExit
		os.Args = originalArguments
		standardOutput, standardError = originalOutput, originalError
	})
	var code int
	exitProcess = func(value int) { code = value }
	standardOutput, standardError = io.Discard, io.Discard
	os.Args = []string{"secverify", "help"}
	main()
	if code != exitPass {
		t.Fatalf("main exit = %d", code)
	}
}

func TestDispatchOwnedProcess(t *testing.T) {
	t.Parallel()
	var code int
	dispatch := func([]string) (bool, int) { return true, 7 }
	if !dispatchOwnedProcess(nil, func(value int) { code = value }, dispatch) || code != 7 {
		t.Fatalf("dispatch = %d", code)
	}
	if dispatchOwnedProcess(nil, func(int) { t.Fatal("ordinary dispatch exited") }, func([]string) (bool, int) { return false, 0 }) {
		t.Fatal("ordinary dispatch was handled")
	}
}

func TestRunMainDispatchesOwnedProcess(t *testing.T) {
	t.Parallel()
	var code int
	runMain(nil, io.Discard, io.Discard, func(value int) { code = value }, func([]string) (bool, int) { return true, 9 })
	if code != 9 {
		t.Fatalf("runMain exit = %d", code)
	}
}

func TestRunInternalDispatch(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if code, handled := runInternal(t.Context(), root, nil, strings.NewReader(""), io.Discard, io.Discard); handled || code != 0 {
		t.Fatalf("ordinary dispatch = (%d, %t)", code, handled)
	}
	if code, handled := runInternal(t.Context(), root, []string{"unknown"}, strings.NewReader(""), io.Discard, io.Discard); handled || code != 0 {
		t.Fatalf("unknown dispatch = (%d, %t)", code, handled)
	}
	input := operationReader(t, "__go-coverage-self-test", struct{}{}, struct{}{})
	if code, handled := runInternal(t.Context(), root, []string{"__go-coverage-self-test"}, input, io.Discard, io.Discard); !handled || code != exitPass {
		t.Fatalf("coverage self-test = (%d, %t)", code, handled)
	}
	input = operationReader(t, "__go-coverage-self-test", struct{}{}, struct{}{})
	code := runWithParserInput(t.Context(), []string{"secverify", "__go-coverage-self-test"}, input, io.Discard, io.Discard,
		func() (string, error) { t.Fatal("internal operation resolved a directory"); return "", nil },
		func(context.Context, string, string) (verify.Plan, error) {
			t.Fatal("internal operation built a plan")
			return verify.Plan{}, nil
		},
		func() (commandline.Parser, error) {
			t.Fatal("internal operation built a parser")
			return commandline.Parser{}, nil
		})
	if code != exitPass {
		t.Fatalf("internal entry point exit = %d", code)
	}
}

func TestRunInternalFailures(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if code, handled := runInternal(cancelled, root, []string{"__go-coverage:0"}, strings.NewReader(""), io.Discard, io.Discard); !handled || code != exitCancelled {
		t.Fatalf("cancelled coverage = (%d, %t)", code, handled)
	}
	if code, handled := runInternal(t.Context(), t.TempDir(), []string{"__go-fuzz-inventory"}, strings.NewReader(""), io.Discard, io.Discard); !handled || code != exitInvocation {
		t.Fatalf("missing fuzz inventory = (%d, %t)", code, handled)
	}
	if code, handled := internalResult(io.Discard, errors.New("internal")); !handled || code != exitFail {
		t.Fatalf("internal failure = (%d, %t)", code, handled)
	}
}

func TestRunInternalFromCurrentBoundaries(t *testing.T) {
	if code, handled := runInternalFromCurrent(t.Context(), []string{"ordinary"}, strings.NewReader(""), io.Discard, io.Discard, nil); handled || code != 0 {
		t.Fatalf("ordinary invocation = (%d, %t)", code, handled)
	}
	input := operationReader(t, "__go-coverage-self-test", struct{}{}, struct{}{})
	if code, handled := runInternalFromCurrent(t.Context(), []string{"__go-coverage-self-test"}, input, io.Discard, io.Discard,
		func() (string, error) {
			t.Fatal("coverage self-test resolved a repository")
			return "", nil
		}); !handled || code != exitPass {
		t.Fatalf("coverage self-test = (%d, %t)", code, handled)
	}
	failure := errors.New("directory")
	if code, handled := runInternalFromCurrent(t.Context(), []string{"__go-fuzz-inventory"}, strings.NewReader(""), io.Discard, io.Discard,
		func() (string, error) { return "", failure }); !handled || code != exitFail {
		t.Fatalf("directory failure = (%d, %t)", code, handled)
	}
	if code, handled := runInternalFromCurrent(t.Context(), []string{"__go-fuzz-inventory"}, strings.NewReader(""), io.Discard, io.Discard,
		func() (string, error) { return "relative", nil }); !handled || code != exitInvocation {
		t.Fatalf("relative directory = (%d, %t)", code, handled)
	}
}

func TestRunInternalRejectsCommonOperationFailures(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if code, handled := runInternal(t.Context(), root, []string{"__go-unknown"}, strings.NewReader(""), io.Discard, io.Discard); handled || code != 0 {
		t.Fatalf("unknown common operation = (%d, %t)", code, handled)
	}
	if code, handled := runInternal(t.Context(), root, []string{"__go-coverage", "extra"}, strings.NewReader(""), io.Discard, io.Discard); handled || code != 0 {
		t.Fatalf("multiple internal arguments = (%d, %t)", code, handled)
	}
}

func TestRunInternalFuzzInventory(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var inventory bytes.Buffer
	targets := []goverify.FuzzTarget{
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzCheckCoverage", Directory: ".", Argument: "."},
		{Module: "example.test/module", Package: "example.test/module", Name: "FuzzSourceTargets", Directory: ".", Argument: "."},
	}
	input := operationReader(t, "__go-fuzz-inventory", struct{}{}, targets)
	if code, handled := runInternalFromCurrent(t.Context(), []string{"__go-fuzz-inventory"}, input, &inventory, io.Discard,
		func() (string, error) { return root, nil }); !handled || code != exitPass ||
		!strings.Contains(inventory.String(), "FuzzCheckCoverage") || !strings.Contains(inventory.String(), "FuzzSourceTargets") {
		t.Fatalf("fuzz inventory = (%d, %t, %q)", code, handled, inventory.String())
	}
}

func TestWriteFailureClasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		code int
	}{
		{err: context.Canceled, code: exitCancelled},
		{err: verify.ErrInvocation, code: exitInvocation},
		{err: verify.ErrInvalidPlan, code: exitInvocation},
		{err: verify.ErrUnavailable, code: exitUnavailable},
		{err: errors.New("failure"), code: exitFail},
	}
	for _, test := range tests {
		var output bytes.Buffer
		if code := writeFailure(&output, test.err); code != test.code || output.Len() == 0 {
			t.Fatalf("writeFailure = (%d, %q)", code, output.String())
		}
	}
	checkWriteFailures(t)
	var output bytes.Buffer
	if code := writeFailure(&output, errors.New("failure\n::warning::value\x1b")); code != exitFail ||
		output.String() != "secverify: failure\\x0a\\x3a:warning::value\\x1b\n" {
		t.Fatalf("safe failure = (%d, %q)", code, output.String())
	}
}

func checkWriteFailures(t *testing.T) {
	t.Helper()
	if code := writeFailure(errorWriter{}, errors.New("failure")); code != exitInvocation {
		t.Fatalf("writer failure exit = %d", code)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }
