package goverify

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
)

func TestVerifyWorkflowCurrency(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1.2.0"))
	git := workflowGitTool(t)
	tags := actionTags(
		actionTagFixture{commit: strings.Repeat("b", workflowCommitBytes), version: "v1.0.0"},
		actionTagFixture{commit: commit, version: "v1.2.0"},
	)
	runner := func(_ context.Context, command proctree.Command) (proctree.Result, error) {
		want := []string{"--git-dir=" + os.DevNull, "-c", "credential.helper=", "ls-remote", "--tags", "https://github.com/actions/checkout.git"}
		if command.Directory != root || !reflect.DeepEqual(command.Arguments, want) {
			t.Fatalf("command = %#v", command)
		}
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: tags}, nil
	}
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWorkflowCurrencyIncludesLocalActions(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	writeDiscoveryFile(t, root, ".github/actions/check/action.yml",
		"name: check\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@"+commit+" # v1.0.0\n")
	runner := fixedWorkflowCurrencyRunner(actionTags(actionTagFixture{commit: commit, version: "v1.0.0"}))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), runner); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWorkflowCurrencyOwnsEnvironment(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1.0.0"))
	git := workflowGitTool(t)
	git.Environment = []string{"VALUE=before"}
	environment := git.Environment
	runner := func(_ context.Context, command proctree.Command) (proctree.Result, error) {
		environment[0] = "VALUE=after"
		if !reflect.DeepEqual(command.Environment, []string{"VALUE=before"}) {
			t.Fatalf("environment = %#v", command.Environment)
		}
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: actionTags(actionTagFixture{commit: commit, version: "v1.0.0"})}, nil
	}
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWorkflowCurrencyRequiresCurrentTag(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	current := strings.Repeat("a", workflowCommitBytes)
	latest := strings.Repeat("b", workflowCommitBytes)
	git := workflowGitTool(t)
	tags := actionTags(actionTagFixture{commit: current, version: "v1.2.0"}, actionTagFixture{commit: latest, version: "v2.0.0"})
	runner := fixedWorkflowCurrencyRunner(tags)
	for _, annotation := range []string{"", "v1.2.0", "v1.2.0; exclude v1.9.0: incompatible"} {
		writeDiscoveryFile(t, root, path, actionWorkflow(current, annotation))
		if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); !errors.Is(err, ErrWorkflowCurrency) {
			t.Fatalf("annotation %q error = %v", annotation, err)
		}
	}
	writeDiscoveryFile(t, root, path, actionWorkflow(current, "v1.2.0; exclude v2.0.0: requires a later runtime"))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); err != nil {
		t.Fatalf("exclusion error = %v", err)
	}
	writeDiscoveryFile(t, root, path, actionWorkflow(latest, "v2.0.0; exclude v2.0.0: stale"))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("stale exclusion error = %v", err)
	}
}

func TestWorkflowExclusionRequiresHighestRemainingTag(t *testing.T) {
	current := strings.Repeat("a", workflowCommitBytes)
	tags, err := parseActionTags(actionTags(
		actionTagFixture{commit: current, version: "v1.2.0"},
		actionTagFixture{commit: strings.Repeat("b", workflowCommitBytes), version: "v1.9.0"},
		actionTagFixture{commit: strings.Repeat("d", workflowCommitBytes), version: "v2"},
		actionTagFixture{commit: strings.Repeat("e", workflowCommitBytes), version: "v2.0"},
		actionTagFixture{commit: strings.Repeat("c", workflowCommitBytes), version: "v2.0.0"},
	))
	if err != nil {
		t.Fatal(err)
	}
	reference := WorkflowReference{
		Kind: WorkflowAction, Value: "actions/checkout@" + current, Version: "v1.2.0",
		ExcludedVersion: "v2.0.0", ExclusionReason: "requires another runtime", Line: 1,
	}
	if err = verifyActionReference(reference, tags); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("skipped compatible update error = %v", err)
	}
	reference.Version = "v1.9.0"
	reference.Value = "actions/checkout@" + strings.Repeat("b", workflowCommitBytes)
	if err = verifyActionReference(reference, tags); err != nil {
		t.Fatalf("highest remaining tag error = %v", err)
	}
}

func TestVerifyWorkflowCurrencyRequiresCommentToMatchPinnedVersion(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	tags := actionTags(
		actionTagFixture{commit: strings.Repeat("b", workflowCommitBytes), version: "v1.1.0"},
		actionTagFixture{commit: commit, version: "v1.2.0"},
	)
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1.1.0"))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(tags)); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("mismatched comment error = %v", err)
	}
}

func TestVerifyWorkflowCurrencyRequiresExactLatestTagName(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	tags := actionTags(
		actionTagFixture{commit: commit, version: "v1"},
		actionTagFixture{commit: commit, version: "v1.0.0"},
	)
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1"))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(tags)); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("version alias error = %v", err)
	}
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1.0.0"))
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(tags)); err != nil {
		t.Fatalf("exact version error = %v", err)
	}
}

func TestVerifyWorkflowCurrencyRejectsResolverFailures(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	commit := strings.Repeat("a", workflowCommitBytes)
	writeDiscoveryFile(t, root, path, actionWorkflow(commit, "v1.0.0"))
	git := workflowGitTool(t)
	for _, outcome := range []struct {
		result proctree.Result
		err    error
	}{
		{},
		{result: proctree.Result{Started: true, ExitCode: 1, Outcome: proctree.OutcomeExitFailure}, err: proctree.ErrExit},
		{result: proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted}, err: errors.New("run")},
		{result: proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: []byte("invalid\n")}},
	} {
		runner := func(context.Context, proctree.Command) (proctree.Result, error) { return outcome.result, outcome.err }
		if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, runner); !errors.Is(err, ErrWorkflowCurrency) {
			t.Fatalf("resolver error = %v", err)
		}
	}
	if err := VerifyWorkflowCurrency(nilContext(), root, []string{path}, git); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("public boundary error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	runner := func(context.Context, proctree.Command) (proctree.Result, error) {
		cancel()
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: actionTags(actionTagFixture{commit: commit, version: "v1.0.0"})}, nil
	}
	if err := verifyWorkflowCurrencyWith(ctx, root, []string{path}, git, runner); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolver cancellation error = %v", err)
	}
	writeDiscoveryFile(t, root, path, "jobs: [\n")
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, git, fixedWorkflowCurrencyRunner(nil)); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("workflow read error = %v", err)
	}
}

func TestReadWorkflowDependenciesRejectsFailures(t *testing.T) {
	missing := t.TempDir() + string(os.PathSeparator) + "missing"
	if _, err := readWorkflowDependencies(t.Context(), missing, []string{".github/workflows/core.yml"}); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("missing root error = %v", err)
	}
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	if _, err := readWorkflowDependencies(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("missing workflow error = %v", err)
	}
	writeDiscoveryFile(t, root, path, "jobs:\n  call:\n    uses: ./.github/workflows/missing.yml\n")
	if _, err := readWorkflowDependencies(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("local workflow error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readWorkflowDependencies(cancelled, root, []string{path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	failure := errors.New("close")
	if err := workflowCurrencyClose(failure); !errors.Is(err, failure) || workflowCurrencyClose(nil) != nil {
		t.Fatalf("close error = %v", err)
	}
	overflowRoot := t.TempDir()
	overflowPaths := []string{".github/workflows/a.yml", ".github/workflows/b.yml"}
	var source strings.Builder
	source.WriteString("jobs:\n  build:\n    steps:\n")
	for range MaxWorkflowReferences {
		source.WriteString("      - uses: ./.github/workflows/a.yml\n")
	}
	writeDiscoveryFile(t, overflowRoot, overflowPaths[0], source.String())
	writeDiscoveryFile(t, overflowRoot, overflowPaths[1], workflowStep("uses: ./.github/workflows/a.yml"))
	if _, err := readWorkflowDependencies(t.Context(), overflowRoot, overflowPaths); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("cumulative reference bound error = %v", err)
	}
}

func TestVerifyWorkflowCurrencyObservesCancellationWithoutRemoteActions(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, "jobs: {}\n")
	ctx := &stagedContext{Context: t.Context(), failAt: 2}
	err := verifyWorkflowCurrencyWith(ctx, root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(nil))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("final cancellation error = %v", err)
	}
}

func TestParseActionTags(t *testing.T) {
	base := strings.Repeat("a", workflowCommitBytes)
	peeled := strings.Repeat("b", workflowCommitBytes)
	tags, err := parseActionTags([]byte(base + "\trefs/tags/v1.0.0\n" + peeled + "\trefs/tags/v1.0.0^{}\n" + base + "\trefs/tags/not-a-version\n"))
	if err != nil || tags["v1.0.0"].commit != peeled {
		t.Fatalf("tags = (%#v, %v)", tags, err)
	}
	for _, source := range [][]byte{
		nil,
		[]byte("invalid\n"),
		[]byte(base + "\trefs/tags/v1.0.0\n" + base + "\trefs/tags/v1.0.0\n"),
		[]byte(base + "\trefs/tags/v1.0.0^{}\n" + base + "\trefs/tags/v1.0.0^{}\n"),
		[]byte(base + "\trefs/tags/v1.0.0^{}\n"),
		[]byte(base + "\tHEAD\n"),
		[]byte(base + "\trefs/tags/^{}\n"),
	} {
		if _, err := parseActionTags(source); !errors.Is(err, ErrWorkflowCurrency) {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
}

func TestWorkflowVersionParsing(t *testing.T) {
	for _, value := range []string{"v1", "v1.2", "v1.2.3", "v18446744073709551616.0.0"} {
		if _, valid := parseActionVersion(value); !valid {
			t.Fatalf("version %q rejected", value)
		}
	}
	for _, value := range []string{"", "1.0.0", "v", "v01", "v1.2.3.4", "v1.2.rc1"} {
		if _, valid := parseActionVersion(value); valid {
			t.Fatalf("version %q accepted", value)
		}
	}
	left, _ := parseActionVersion("v1.9.0")
	right, _ := parseActionVersion("v2.0.0")
	if compareActionVersion(left, right) >= 0 {
		t.Fatal("version comparison differs")
	}
	for _, annotation := range []string{"latest", "v1; exclude latest: reason", "v1; exclude v2", "v1; exclude v2: "} {
		if _, err := parseWorkflowVersionAnnotation(annotation); !errors.Is(err, ErrWorkflowCurrency) {
			t.Fatalf("annotation %q error = %v", annotation, err)
		}
	}
	if _, err := parseWorkflowVersionAnnotation("v1; exclude v2: " + strings.Repeat("x", maxWorkflowExclusionReasonBytes+1)); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("long annotation error = %v", err)
	}
}

func FuzzActionVersion(f *testing.F) {
	f.Add("v1.2.3")
	f.Add("v18446744073709551616.0.0")
	f.Add("v01.0.0")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > MaxWorkflowLineBytes {
			return
		}
		first, firstValid := parseActionVersion(value)
		second, secondValid := parseActionVersion(value)
		if firstValid != secondValid || first != second {
			t.Fatal("action version parsing differs")
		}
		if firstValid && compareActionVersion(first, first) != 0 {
			t.Fatal("action version differs from itself")
		}
	})
}

func FuzzActionTags(f *testing.F) {
	commit := strings.Repeat("a", workflowCommitBytes)
	f.Add([]byte(commit + "\trefs/tags/v1.0.0\n"))
	f.Add([]byte(commit + "\trefs/tags/v1.0.0^{}\n"))
	f.Add([]byte("invalid\n"))
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxRepositoryCommandBytes {
			return
		}
		first, firstErr := parseActionTags(source)
		second, secondErr := parseActionTags(source)
		if !reflect.DeepEqual(first, second) || (firstErr == nil) != (secondErr == nil) ||
			errors.Is(firstErr, ErrWorkflowCurrency) != errors.Is(secondErr, ErrWorkflowCurrency) {
			t.Fatal("action tag parsing differs")
		}
		if firstErr != nil {
			return
		}
		for name, tag := range first {
			if _, valid := parseActionVersion(name); !valid || !tag.base || !lowerHex(tag.commit, workflowCommitBytes) {
				t.Fatalf("invalid action tag = (%q, %#v)", name, tag)
			}
		}
	})
}

func TestVerifyWorkflowCurrencyRetainsLargeStableVersions(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	current := strings.Repeat("a", workflowCommitBytes)
	latest := strings.Repeat("b", workflowCommitBytes)
	writeDiscoveryFile(t, root, path, actionWorkflow(current, "v1.0.0"))
	tags := actionTags(
		actionTagFixture{commit: current, version: "v1.0.0"},
		actionTagFixture{commit: latest, version: "v18446744073709551616.0.0"},
	)
	if err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(tags)); !errors.Is(err, ErrWorkflowCurrency) {
		t.Fatalf("large stable update error = %v", err)
	}
}

func TestWorkflowActionIdentity(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	if repository := workflowActionRepository("actions/checkout/path@" + commit); repository != "actions/checkout" {
		t.Fatalf("repository = %q", repository)
	}
	for _, value := range []string{"./.github/workflows/core.yml", "docker://image@sha256:value", "invalid", "owner@" + commit} {
		if repository := workflowActionRepository(value); repository != "" {
			t.Fatalf("repository %q = %q", value, repository)
		}
	}
}

func TestWorkflowCurrencyErrorsIncludeOwningPath(t *testing.T) {
	current := strings.Repeat("a", workflowCommitBytes)
	latest := strings.Repeat("b", workflowCommitBytes)
	tags := actionTags(
		actionTagFixture{commit: current, version: "v1.0.0"},
		actionTagFixture{commit: latest, version: "v2.0.0"},
	)
	for _, test := range []struct {
		name     string
		workflow string
		action   string
		pathLine string
	}{
		{name: "workflow", workflow: actionWorkflow(current, "v1.0.0"), pathLine: ".github/workflows/core.yml:4"},
		{name: "local action", workflow: workflowStep("uses: ./.github/actions/check"),
			action:   "name: check\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + current + " # v1.0.0\n",
			pathLine: ".github/actions/check/action.yml:5"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := ".github/workflows/core.yml"
			writeDiscoveryFile(t, root, path, test.workflow)
			if test.action != "" {
				writeDiscoveryFile(t, root, ".github/actions/check/action.yml", test.action)
			}
			err := verifyWorkflowCurrencyWith(t.Context(), root, []string{path}, workflowGitTool(t), fixedWorkflowCurrencyRunner(tags))
			if !errors.Is(err, ErrWorkflowCurrency) || !strings.Contains(err.Error(), test.pathLine) {
				t.Fatalf("workflow diagnostic = %v", err)
			}
		})
	}
}

func workflowGitTool(t *testing.T) Tool {
	t.Helper()
	return Tool{Executable: testExecutable(t), Timeout: time.Minute, OutputLimit: MaxRepositoryCommandBytes}
}

func fixedWorkflowCurrencyRunner(output []byte) workflowCurrencyRun {
	return func(context.Context, proctree.Command) (proctree.Result, error) {
		return proctree.Result{Started: true, Outcome: proctree.OutcomeCompleted, Stdout: output}, nil
	}
}

func actionWorkflow(commit, annotation string) string {
	comment := ""
	if annotation != "" {
		comment = " # " + annotation
	}
	return "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + commit + comment + "\n"
}

type actionTagFixture struct {
	commit  string
	version string
}

func actionTags(values ...actionTagFixture) []byte {
	var output strings.Builder
	for _, value := range values {
		output.WriteString(value.commit)
		output.WriteString("\trefs/tags/")
		output.WriteString(value.version)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}
