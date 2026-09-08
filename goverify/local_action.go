package goverify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const MaxLocalActionBytes = 16 << 20
const MaxLocalActions = MaxRepositorySources

type localActionOwner struct {
	ctx        context.Context
	root       *os.Root
	open       func(string) (*os.File, error)
	workflows  []string
	visited    map[string]bool
	active     map[string]bool
	actions    int
	bytes      int
	references int
}

func newLocalActionOwner(ctx context.Context, root *os.Root, workflows []string) *localActionOwner {
	return &localActionOwner{
		ctx: ctx, root: root, open: root.Open, workflows: workflows, visited: make(map[string]bool), active: make(map[string]bool),
	}
}

func (owner *localActionOwner) expand(references []WorkflowReference) ([]WorkflowReference, error) {
	result := make([]WorkflowReference, 0, len(references))
	for _, reference := range references {
		if err := owner.add(&result, reference); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (owner *localActionOwner) add(result *[]WorkflowReference, reference WorkflowReference) error {
	if err := owner.ctx.Err(); err != nil {
		return errors.Join(ErrWorkflowReferences, err)
	}
	if owner.references == MaxWorkflowReferences {
		return ErrWorkflowReferences
	}
	owner.references++
	if local, found := strings.CutPrefix(reference.Value, "./.github/workflows/"); found {
		if _, found = slices.BinarySearch(owner.workflows, ".github/workflows/"+local); !found {
			return ErrWorkflowReferences
		}
		return nil
	}
	local, found := localActionDirectory(reference.Value)
	if !found {
		*result = append(*result, reference)
		return nil
	}
	return owner.addLocalAction(result, local)
}

func (owner *localActionOwner) addLocalAction(result *[]WorkflowReference, directory string) error {
	if owner.active[directory] {
		return ErrWorkflowReferences
	}
	if owner.visited[directory] {
		return nil
	}
	if owner.actions == MaxLocalActions {
		return ErrWorkflowReferences
	}
	owner.actions++
	owner.active[directory] = true
	defer delete(owner.active, directory)
	source, path, err := owner.read(directory)
	if err != nil {
		return err
	}
	references, err := inspectLocalActionReferences(source)
	if err != nil {
		return fmt.Errorf("%s: %w", path, errors.Join(ErrWorkflowReferences, err))
	}
	for index := range references {
		references[index].Path = path
	}
	for _, reference := range references {
		if err = owner.add(result, reference); err != nil {
			return err
		}
	}
	owner.visited[directory] = true
	return nil
}

func (owner *localActionOwner) read(directory string) ([]byte, string, error) {
	if err := owner.ctx.Err(); err != nil {
		return nil, "", errors.Join(ErrWorkflowReferences, err)
	}
	metadata := ""
	for _, name := range []string{"action.yml", "action.yaml"} {
		candidate := filepath.Join(filepath.FromSlash(directory), name)
		admitErr := admitRootPath(owner.root, candidate, false)
		if errors.Is(admitErr, os.ErrNotExist) {
			continue
		}
		if admitErr != nil {
			return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(candidate), errors.Join(ErrWorkflowReferences, admitErr))
		}
		if metadata != "" {
			return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(candidate), ErrWorkflowReferences)
		}
		metadata = candidate
	}
	if metadata == "" {
		return nil, "", ErrWorkflowReferences
	}
	file, err := owner.open(metadata)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(metadata), errors.Join(ErrWorkflowReferences, err))
	}
	source, err := readBoundedSourceLimit(boundedSource{reader: file, stat: file.Stat, close: file.Close}, ErrWorkflowReferences, MaxWorkflowBytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(metadata), err)
	}
	if len(source) > MaxLocalActionBytes-owner.bytes {
		return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(metadata), ErrWorkflowReferences)
	}
	owner.bytes += len(source)
	return source, filepath.ToSlash(metadata), nil
}

func inspectLocalActionReferences(source []byte) ([]WorkflowReference, error) {
	if len(source) > MaxWorkflowBytes || !utf8.Valid(source) || !validWorkflowLines(source) {
		return nil, ErrWorkflowReferences
	}
	root, err := decodeWorkflow(source)
	if err != nil || root.Kind != yaml.MappingNode {
		return nil, errors.Join(ErrWorkflowReferences, err)
	}
	runs, using, err := localActionRuns(root)
	if err != nil {
		return nil, err
	}
	return localActionRunReferences(runs, using)
}

func localActionRuns(root *yaml.Node) (*yaml.Node, string, error) {
	runs, found := workflowField(root, "runs")
	if !found || runs.Kind != yaml.MappingNode {
		return nil, "", ErrWorkflowReferences
	}
	using, found := workflowField(runs, "using")
	if !found || using.Kind != yaml.ScalarNode || using.Tag != "!!str" || using.Value == "" {
		return nil, "", ErrWorkflowReferences
	}
	return runs, using.Value, nil
}

func localActionRunReferences(runs *yaml.Node, using string) ([]WorkflowReference, error) {
	var references []WorkflowReference
	var err error
	switch using {
	case "composite":
		if _, found := workflowField(runs, "steps"); !found {
			return nil, ErrWorkflowReferences
		}
		err = appendStepReferences(&references, runs)
	case "docker":
		image, imageFound := workflowField(runs, "image")
		if !imageFound || image.Kind != yaml.ScalarNode || image.Tag != "!!str" || image.Value == "" {
			return nil, ErrWorkflowReferences
		}
		if strings.HasPrefix(image.Value, "docker://") {
			err = appendWorkflowReference(&references, WorkflowAction, image)
		}
	}
	return references, err
}
