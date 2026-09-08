package goverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestInspectWorkflowReferences(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	digest := strings.Repeat("b", workflowDigestBytes)
	source := "name: Checked\non: push\njobs:\n" +
		"  local:\n    uses: ./.github/workflows/core.yml\n" +
		"  build:\n    runs-on: ubuntu-latest\n    container: registry.test/build@sha256:" + digest + "\n" +
		"    steps:\n      - uses: actions/checkout@" + commit + " # v1.2.3\n" +
		"      - uses: 'docker://registry.test/check@sha256:" + digest + "'\n"
	references, err := InspectWorkflowReferences([]byte(source))
	want := []WorkflowReference{
		{Kind: WorkflowAction, Value: "./.github/workflows/core.yml", Line: 5},
		{Kind: WorkflowImage, Value: "registry.test/build@sha256:" + digest, Line: 8},
		{Kind: WorkflowAction, Value: "actions/checkout@" + commit, Version: "v1.2.3", Line: 10},
		{Kind: WorkflowAction, Value: "docker://registry.test/check@sha256:" + digest, Line: 11},
	}
	if err != nil || !reflect.DeepEqual(references, want) {
		t.Fatalf("references = (%#v, %v)", references, err)
	}
}

func TestInspectWorkflowReferencesRejectsInvalidMaterial(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	digest := strings.Repeat("b", workflowDigestBytes)
	for _, source := range []string{
		workflowStep("uses: actions/checkout@main"),
		workflowStep("uses: owner@" + commit),
		workflowStep("uses: owner/repository@" + strings.ToUpper(commit)),
		workflowStep("uses: docker://registry.test/image:latest"),
		workflowStep("uses: actions/checkout@" + commit + " # invalid-version"),
		"jobs:\n  build:\n    container: registry.test/image:latest\n",
		"jobs:\n  build:\n    services:\n      database:\n        image: registry.test/image@sha256:" + digest + "@extra\n",
		"---",
		"...",
		"<<: *uses",
		"*u: actions/checkout@" + commit,
		"jobs: {build: {services: {db: {image: registry.test/db:latest}}}}",
		strings.Repeat("x", MaxWorkflowLineBytes+1),
	} {
		if _, err := InspectWorkflowReferences([]byte(source)); !errors.Is(err, ErrWorkflowReferences) {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
	if _, err := InspectWorkflowReferences([]byte{0xff}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("UTF-8 error = %v", err)
	}
	if _, err := InspectWorkflowReferences(make([]byte, MaxWorkflowBytes+1)); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("source bound error = %v", err)
	}
}

func TestInspectWorkflowReferencesAcceptsFlowMappings(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	references, err := InspectWorkflowReferences([]byte("jobs: {build: {steps: [{uses: actions/checkout@" + commit + "}]}}\n"))
	if err != nil || len(references) != 1 || references[0].Value != "actions/checkout@"+commit {
		t.Fatalf("flow references = (%#v, %v)", references, err)
	}
}

func TestInspectWorkflowReferencesRejectsAmbiguousStructures(t *testing.T) {
	for _, source := range []string{
		"jobs: {}\njobs: {}\n",
		"jobs: []\n",
		"jobs:\n  build: value\n",
		"jobs:\n  call:\n    uses: actions/checkout@main\n",
		"jobs:\n  build:\n    services: []\n",
		"jobs:\n  build:\n    services:\n      database: value\n",
		"jobs:\n  build:\n    steps: value\n",
		"jobs:\n  build:\n    steps: [value]\n",
		"jobs:\n  build:\n    container: {}\n",
		"jobs:\n  build:\n    container: []\n",
		"jobs: !custom {}\n",
		"jobs: {}\n---\njobs: {}\n",
	} {
		if _, err := InspectWorkflowReferences([]byte(source)); !errors.Is(err, ErrWorkflowReferences) {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
}

func TestInspectWorkflowReferencesExpandsAnchoredJobs(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	source := "jobs:\n  build: &build\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + commit + " # v1.2.3\n  copy: *build\n"
	references, err := InspectWorkflowReferences([]byte(source))
	if err != nil || len(references) != 2 {
		t.Fatalf("anchored references = (%#v, %v)", references, err)
	}
	for _, reference := range references {
		if reference.Value != "actions/checkout@"+commit || reference.Version != "v1.2.3" {
			t.Fatalf("anchored reference = %#v", reference)
		}
	}
}

func TestWorkflowScalarAliasRetainsExecutionSite(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	source := "action: &action actions/checkout@" + commit + " # v1.0.0\njobs:\n  build:\n    steps:\n      - uses: *action # v2.0.0\n"
	references, err := InspectWorkflowReferences([]byte(source))
	want := []WorkflowReference{{Kind: WorkflowAction, Value: "actions/checkout@" + commit, Version: "v2.0.0", Line: 5}}
	if err != nil || !reflect.DeepEqual(references, want) {
		t.Fatalf("scalar alias = (%#v, %v)", references, err)
	}
}

func TestWorkflowAliasExpansionRejectsCyclesAndExpandedBounds(t *testing.T) {
	if _, err := expandWorkflowAliases(nil, MaxWorkflowNodes); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("nil expansion error = %v", err)
	}
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "value"}
	owner := workflowExpansion{maximum: MaxWorkflowNodes, active: make(map[*yaml.Node]bool)}
	if _, err := owner.expand(scalar, MaxWorkflowDepth+1); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("depth error = %v", err)
	}
	if _, err := expandWorkflowAliases(scalar, 0); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("zero bound error = %v", err)
	}
	left := &yaml.Node{Kind: yaml.AliasNode}
	right := &yaml.Node{Kind: yaml.AliasNode, Alias: left}
	left.Alias = right
	if _, err := expandWorkflowAliases(left, MaxWorkflowNodes); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("alias cycle error = %v", err)
	}
	cycle := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	cycle.Content = []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "self"},
		{Kind: yaml.AliasNode, Alias: cycle},
	}
	if _, err := expandWorkflowAliases(cycle, MaxWorkflowNodes); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("cycle error = %v", err)
	}
	cycleSource := []byte("jobs:\n  build: &build\n    env:\n      SELF: *build\n")
	if _, err := InspectWorkflowReferences(cycleSource); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("source cycle error = %v", err)
	}
	target := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "one"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "two"},
	}}
	root := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
		{Kind: yaml.AliasNode, Alias: target},
		{Kind: yaml.AliasNode, Alias: target},
	}}
	if _, err := expandWorkflowAliases(root, len(root.Content)+len(target.Content)); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("expanded bound error = %v", err)
	}
}

func TestWorkflowTreeBoundsAndNodeKinds(t *testing.T) {
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "value"}
	wide := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: make([]*yaml.Node, MaxWorkflowNodes+1)}
	for index := range wide.Content {
		wide.Content[index] = scalar
	}
	if validWorkflowTree(wide) {
		t.Fatal("node bound accepted")
	}
	deep := scalar
	for range MaxWorkflowDepth + 1 {
		deep = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{deep}}
	}
	if validWorkflowTree(deep) {
		t.Fatal("depth bound accepted")
	}
	for _, node := range []*yaml.Node{
		nil,
		{},
		{Kind: yaml.AliasNode},
		{Kind: yaml.ScalarNode, Tag: "!!str", Alias: scalar},
		{Kind: yaml.DocumentNode, Content: []*yaml.Node{scalar, scalar}},
		{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{scalar}},
		{Kind: yaml.SequenceNode, Tag: "!custom"},
		{Kind: yaml.ScalarNode, Tag: "!custom"},
	} {
		if validWorkflowNode(node) {
			t.Fatalf("invalid node accepted: %#v", node)
		}
	}
	for _, mapping := range []*yaml.Node{
		{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.SequenceNode}, scalar}},
		{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "<<"}, scalar}},
		{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "same"}, scalar,
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "same"}, scalar,
		}},
	} {
		if uniqueWorkflowKeys(mapping, make(map[string]bool)) {
			t.Fatalf("invalid keys accepted: %#v", mapping)
		}
	}
	if _, found := workflowField(scalar, "value"); found {
		t.Fatal("scalar exposed a mapping field")
	}
}

func TestPinnedYAMLParserDepth(t *testing.T) {
	source := []byte(strings.Repeat("[", MaxWorkflowParserDepth+1))
	if _, err := decodeWorkflow(source); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("parser depth error = %v", err)
	}
}

func TestWorkflowReferenceBound(t *testing.T) {
	references := make([]WorkflowReference, MaxWorkflowReferences)
	value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "./.github/workflows/core.yml"}
	if err := appendWorkflowReference(&references, WorkflowAction, value); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("reference bound error = %v", err)
	}
}

func TestInspectWorkflowReferencesCoversContainerForms(t *testing.T) {
	digest := strings.Repeat("a", workflowDigestBytes)
	source := "jobs:\n  build:\n    container:\n      image: registry.test/build@sha256:" + digest + "\n    services:\n      database:\n        image: registry.test/database@sha256:" + digest + "\n    steps: []\n"
	references, err := InspectWorkflowReferences([]byte(source))
	if err != nil || len(references) != 2 || references[0].Kind != WorkflowImage || references[1].Kind != WorkflowImage {
		t.Fatalf("container references = (%#v, %v)", references, err)
	}
}

func TestInspectWorkflowReferencesOrdersOneLineReferences(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	digest := strings.Repeat("b", workflowDigestBytes)
	source := "jobs: {build: {container: registry.test/build@sha256:" + digest + ", steps: [{uses: actions/checkout@" + commit + "}]}}\n"
	references, err := InspectWorkflowReferences([]byte(source))
	if err != nil || len(references) != 2 || references[0].Value != "actions/checkout@"+commit || references[1].Value != "registry.test/build@sha256:"+digest {
		t.Fatalf("ordered references = (%#v, %v)", references, err)
	}
	references, err = InspectWorkflowReferences([]byte("jobs:\n  build:\n    container:\n"))
	if err != nil || len(references) != 0 {
		t.Fatalf("null container = (%#v, %v)", references, err)
	}
}

func TestVerifyWorkflowReferences(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: actions/checkout@"+strings.Repeat("a", workflowCommitBytes)))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); err != nil {
		t.Fatal(err)
	}
	writeDiscoveryFile(t, root, ".github/actions/check/action.yml", "name: check\nruns: {using: composite, steps: []}\n")
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); err != nil {
		t.Fatalf("local action error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/empty"))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("metadata-free local action error = %v", err)
	}
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/missing"))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("missing local action error = %v", err)
	}
	writeDiscoveryFile(t, root, path, workflowStep("uses: actions/checkout@main"))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("mutable reference error = %v", err)
	}
	reusable := ".github/workflows/reusable.yml"
	writeDiscoveryFile(t, root, path, "jobs:\n  call:\n    uses: ./"+reusable+"\n")
	writeDiscoveryFile(t, root, reusable, "jobs: {}\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path, reusable}); err != nil {
		t.Fatalf("local workflow error = %v", err)
	}
	writeDiscoveryFile(t, root, path, "jobs:\n  call:\n    uses: ./.github/workflows/missing.yml\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("missing local workflow error = %v", err)
	}
}

func TestVerifyWorkflowReferencesInspectsLocalActions(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	action := "name: check\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@main\n"
	writeDiscoveryFile(t, root, ".github/actions/check/action.yml", action)
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("mutable nested action error = %v", err)
	}
	commit := strings.Repeat("a", workflowCommitBytes)
	action = strings.Replace(action, "actions/checkout@main", "actions/checkout@"+commit, 1)
	writeDiscoveryFile(t, root, ".github/actions/check/action.yml", action)
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); err != nil {
		t.Fatalf("pinned nested action error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsLocalActionCyclesAndAmbiguity(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/a"))
	writeDiscoveryFile(t, root, ".github/actions/a/action.yml", "name: a\nruns: {using: composite, steps: [{uses: ./.github/actions/b}]}\n")
	writeDiscoveryFile(t, root, ".github/actions/b/action.yml", "name: b\nruns: {using: composite, steps: [{uses: ./.github/actions/a}]}\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("local action cycle error = %v", err)
	}
	writeDiscoveryFile(t, root, ".github/actions/a/action.yaml", "name: duplicate\nruns: {using: composite, steps: []}\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("duplicate metadata error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsInvalidPrimaryActionMetadata(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	directory := filepath.Join(root, ".github", "actions", "check", "action.yml")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDiscoveryFile(t, root, ".github/actions/check/action.yaml", "name: alternate\nruns: {using: composite, steps: []}\n")
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("invalid primary metadata error = %v", err)
	}
}

func TestInspectLocalActionReferences(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	for _, source := range []string{
		"name: action\nruns: {using: composite, steps: [{uses: actions/checkout@" + commit + "}]}\n",
		"name: action\nruns: {using: docker, image: docker://image@sha256:" + strings.Repeat("a", workflowDigestBytes) + "}\n",
		"name: action\nruns: {using: node24, main: index.js}\n",
	} {
		if _, err := inspectLocalActionReferences([]byte(source)); err != nil {
			t.Fatalf("local action %q error = %v", source, err)
		}
	}
	for _, source := range [][]byte{
		nil,
		{0xff},
		[]byte("[]\n"),
		[]byte("name: action\n"),
		[]byte("runs: []\n"),
		[]byte("runs: {using: null}\n"),
		[]byte("runs: {using: composite}\n"),
		[]byte("runs: {using: docker}\n"),
		[]byte("runs: {using: docker, image: docker://image:latest}\n"),
	} {
		if _, err := inspectLocalActionReferences(source); !errors.Is(err, ErrWorkflowReferences) {
			t.Fatalf("invalid local action %q error = %v", source, err)
		}
	}
}

func TestLocalActionOwnerBounds(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "action.yml", "name: action\nruns: {using: composite, steps: []}\n")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Error(err)
		}
	})
	owner := newLocalActionOwner(t.Context(), opened, nil)
	owner.actions = MaxLocalActions
	if _, err := owner.expand([]WorkflowReference{{Value: "./"}}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("action count error = %v", err)
	}
	owner = newLocalActionOwner(t.Context(), opened, nil)
	owner.bytes = MaxLocalActionBytes
	if _, err := owner.expand([]WorkflowReference{{Value: "./"}}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("action bytes error = %v", err)
	}
	owner = newLocalActionOwner(t.Context(), opened, nil)
	owner.references = MaxWorkflowReferences
	if _, err := owner.expand([]WorkflowReference{{Value: "remote/action@" + strings.Repeat("a", workflowCommitBytes)}}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("reference count error = %v", err)
	}
	owner = newLocalActionOwner(t.Context(), opened, nil)
	owner.open = func(string) (*os.File, error) { return nil, errors.New("removed") }
	if _, err := owner.expand([]WorkflowReference{{Value: "./"}}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("metadata open error = %v", err)
	}
	owner = newLocalActionOwner(&stagedContext{Context: t.Context(), failAt: 2}, opened, nil)
	if _, err := owner.expand([]WorkflowReference{{Value: "./"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("metadata cancellation error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	owner = newLocalActionOwner(cancelled, opened, nil)
	if _, err := owner.expand([]WorkflowReference{{Value: "./"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("reference cancellation error = %v", err)
	}
}

func TestLocalActionOwnerReusesValidatedMetadata(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "action.yml", "name: action\nruns: {using: composite, steps: []}\n")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Error(err)
		}
	})
	owner := newLocalActionOwner(t.Context(), opened, nil)
	if _, err = owner.expand([]WorkflowReference{{Value: "./"}, {Value: "./"}}); err != nil || owner.actions != 1 {
		t.Fatalf("reused action = (%d, %v)", owner.actions, err)
	}
}

func TestVerifyWorkflowReferencesRejectsOversizedLocalAction(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/core.yml"
	writeDiscoveryFile(t, root, path, workflowStep("uses: ./.github/actions/check"))
	writeDiscoveryFile(t, root, ".github/actions/check/action.yml", strings.Repeat("x", MaxWorkflowBytes+1))
	if err := VerifyWorkflowReferences(t.Context(), root, []string{path}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("oversized local action error = %v", err)
	}
}

func TestVerifyWorkflowReferencesRejectsInvalidRequests(t *testing.T) {
	root := t.TempDir()
	valid := []string{".github/workflows/core.yml"}
	for _, paths := range [][]string{nil, {"outside.yml"}, {valid[0], valid[0]}, {".github/workflows/z.yml", ".github/workflows/a.yml"}} {
		if err := VerifyWorkflowReferences(t.Context(), root, paths); !errors.Is(err, ErrWorkflowReferences) {
			t.Fatalf("paths %#v error = %v", paths, err)
		}
	}
	if err := VerifyWorkflowReferences(nilContext(), root, valid); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := VerifyWorkflowReferences(t.Context(), ".", valid); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("relative root error = %v", err)
	}
	if err := VerifyWorkflowReferences(t.Context(), filepath.Join(root, "missing"), valid); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("missing root error = %v", err)
	}
	if err := VerifyWorkflowReferences(t.Context(), root, valid); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := VerifyWorkflowReferences(cancelled, root, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	writeDiscoveryFile(t, root, valid[0], "jobs: {}\n")
	staged := &stagedContext{Context: t.Context(), failAt: 2}
	if err := VerifyWorkflowReferences(staged, root, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-read cancellation error = %v", err)
	}
}

func TestWorkflowReferenceHelpers(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	if !immutableWorkflowAction("owner/repository/path@" + commit) {
		t.Fatal("immutable action rejected")
	}
	for _, action := range []string{
		"owner//path@" + commit,
		"../repository@" + commit,
		"owner/repository$@" + commit,
		"./.github/workflows/../action.yml",
	} {
		if immutableWorkflowAction(action) {
			t.Fatalf("invalid action accepted: %q", action)
		}
	}
	for _, image := range []string{
		"@sha256:" + strings.Repeat("a", workflowDigestBytes),
		"image@tag@sha256:" + strings.Repeat("a", workflowDigestBytes),
		"bad image@sha256:" + strings.Repeat("a", workflowDigestBytes),
		"bad\u202eimage@sha256:" + strings.Repeat("a", workflowDigestBytes),
	} {
		if immutableWorkflowImage(image) {
			t.Fatalf("invalid image accepted: %q", image)
		}
	}
	if !workflowRepositoryCharacter('A') || workflowRepositoryCharacter('/') || lowerHex("a", 2) || lowerHex("g", 1) {
		t.Fatal("workflow lexical helper differs")
	}
	if references, err := InspectWorkflowReferences([]byte("container:\n")); err != nil || len(references) != 0 {
		t.Fatalf("empty container = (%#v, %v)", references, err)
	}
}

func TestWorkflowLocalActionHelpers(t *testing.T) {
	for _, action := range []string{"./", "./.github/actions/check"} {
		if !immutableWorkflowAction(action) {
			t.Fatalf("local action rejected: %q", action)
		}
	}
	for _, action := range []string{"../action", "./../action", "./action@revision", ".\x00/action", `.\action`} {
		if immutableWorkflowAction(action) {
			t.Fatalf("invalid local action accepted: %q", action)
		}
	}
	deep := "./" + strings.Repeat("a/", MaxWorkflowPathComponents) + "action"
	if immutableWorkflowAction(deep) {
		t.Fatal("deep local action accepted")
	}
}

func TestInspectWorkflowReferencesAcceptsQuotedKey(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	references, err := InspectWorkflowReferences([]byte(workflowStep(`"uses": actions/checkout@` + commit)))
	if err != nil || len(references) != 1 {
		t.Fatalf("quoted key = (%#v, %v)", references, err)
	}
}

func workflowStep(value string) string {
	return "jobs:\n  build:\n    steps:\n      - " + value + "\n"
}

func TestInspectWorkflowReferencesIgnoresNonExecutionKeys(t *testing.T) {
	commit := strings.Repeat("a", workflowCommitBytes)
	source := "name: Checked\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      image: latest\n    steps:\n      - run: |\n          uses: ordinary text\n          image: ordinary text\n      - uses: actions/checkout@" + commit + "\n"
	references, err := InspectWorkflowReferences([]byte(source))
	want := []WorkflowReference{{Kind: WorkflowAction, Value: "actions/checkout@" + commit, Line: 12}}
	if err != nil || !reflect.DeepEqual(references, want) {
		t.Fatalf("references = (%#v, %v)", references, err)
	}
}

func FuzzInspectWorkflowReferences(f *testing.F) {
	f.Add([]byte("uses: actions/checkout@" + strings.Repeat("a", workflowCommitBytes)))
	f.Add([]byte("uses: actions/checkout@main"))
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxWorkflowBytes+1 {
			return
		}
		first, firstErr := InspectWorkflowReferences(source)
		second, secondErr := InspectWorkflowReferences(source)
		if !reflect.DeepEqual(first, second) || !sameErrorState(firstErr, secondErr) {
			t.Fatalf("inspection differs: (%#v, %v) and (%#v, %v)", first, firstErr, second, secondErr)
		}
		if firstErr == nil && !validWorkflowReferenceSequence(first) {
			t.Fatalf("invalid workflow references = %#v", first)
		}
	})
}

func FuzzInspectLocalActionReferences(f *testing.F) {
	f.Add([]byte("name: action\nruns: {using: composite, steps: []}\n"))
	f.Add([]byte("runs: {using: docker, image: docker://image:latest}\n"))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxWorkflowBytes {
			return
		}
		first, firstErr := inspectLocalActionReferences(source)
		second, secondErr := inspectLocalActionReferences(source)
		if !reflect.DeepEqual(first, second) || (firstErr == nil) != (secondErr == nil) ||
			errors.Is(firstErr, ErrWorkflowReferences) != errors.Is(secondErr, ErrWorkflowReferences) {
			t.Fatal("local action inspection differs")
		}
		for _, reference := range first {
			if reference.Kind != WorkflowAction || !immutableWorkflowAction(reference.Value) {
				t.Fatalf("invalid local action reference = %#v", reference)
			}
		}
	})
}

func validWorkflowReferenceSequence(references []WorkflowReference) bool {
	for index, reference := range references {
		if index > 0 && (references[index-1].Line > reference.Line ||
			references[index-1].Line == reference.Line && references[index-1].Value > reference.Value) {
			return false
		}
		if !validReturnedWorkflowReference(reference) {
			return false
		}
	}
	return true
}

func validReturnedWorkflowReference(reference WorkflowReference) bool {
	if reference.Line <= 0 {
		return false
	}
	switch reference.Kind {
	case WorkflowAction:
		return immutableWorkflowAction(reference.Value)
	case WorkflowImage:
		return immutableWorkflowImage(reference.Value)
	default:
		return false
	}
}

func TestVerifyWorkflowReferencesRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.FromSlash(".github/workflows/core.yml")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, path), make([]byte, MaxWorkflowBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkflowReferences(t.Context(), root, []string{".github/workflows/core.yml"}); !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadWorkflowReferencesRejectsOpenRace(t *testing.T) {
	root := t.TempDir()
	path := ".github/workflows/value.yml"
	writeDiscoveryFile(t, root, path, "jobs: {}\n")
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Error(err)
		}
	})
	_, err = readWorkflowReferencesWith(opened, path, func(string) (*os.File, error) {
		return nil, errors.New("removed")
	})
	if !errors.Is(err, ErrWorkflowReferences) {
		t.Fatalf("open race error = %v", err)
	}
}

func TestAdmitRootPathBoundaries(t *testing.T) {
	missing := errors.New("missing")
	entries := map[string]os.FileInfo{
		".":              workflowInformation{mode: os.ModeDir},
		"directory":      workflowInformation{mode: os.ModeDir},
		"directory/file": workflowInformation{},
		"file":           workflowInformation{},
		"link":           workflowInformation{mode: os.ModeSymlink},
		"special":        workflowInformation{mode: os.ModeNamedPipe},
	}
	lstat := func(path string) (os.FileInfo, error) {
		information, found := entries[filepath.ToSlash(path)]
		if !found {
			return nil, missing
		}
		return information, nil
	}
	for _, test := range []struct {
		path      string
		directory bool
		valid     bool
	}{
		{path: ".", directory: true, valid: true},
		{path: "."},
		{path: ""},
		{path: "file", valid: true},
		{path: "file", directory: true},
		{path: "directory", directory: true, valid: true},
		{path: filepath.Join("directory", "file"), valid: true},
		{path: filepath.Join("file", "child")},
		{path: "link"},
		{path: "special"},
		{path: "missing"},
	} {
		err := admitRootPathWith(test.path, test.directory, lstat)
		if (err == nil) != test.valid {
			t.Fatalf("path %q directory %t error = %v", test.path, test.directory, err)
		}
	}
	if err := admitRootPathWith("missing", false, lstat); !errors.Is(err, missing) {
		t.Fatalf("missing error = %v", err)
	}
	if err := admitRootPathWith(".", true, func(string) (os.FileInfo, error) { return nil, missing }); !errors.Is(err, missing) {
		t.Fatalf("root error = %v", err)
	}
}

type workflowInformation struct {
	os.FileInfo
	mode os.FileMode
}

func (information workflowInformation) Mode() os.FileMode { return information.mode }
func (information workflowInformation) IsDir() bool       { return information.mode.IsDir() }
