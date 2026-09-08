package goverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const MaxWorkflowBytes = 64 << 10
const MaxWorkflowLineBytes = 4 << 10
const MaxWorkflowDepth = 100
const MaxWorkflowParserDepth = 10_000
const MaxWorkflowNodes = MaxWorkflowBytes
const MaxWorkflowReferences = 4 << 10
const MaxWorkflowPathComponents = 64
const workflowCommitBytes = 40
const workflowDigestBytes = 64

var ErrWorkflowReferences = errors.New("invalid workflow execution reference")

// WorkflowReferenceKind distinguishes action and container execution material
type WorkflowReferenceKind uint8

const (
	WorkflowAction WorkflowReferenceKind = iota
	WorkflowImage
)

// WorkflowReference retains one governed execution reference
type WorkflowReference struct {
	Kind            WorkflowReferenceKind // Kind identifies action or image semantics
	Value           string                // Value is the exact source reference
	Version         string                // Version is the adjacent stable action tag
	ExcludedVersion string                // ExcludedVersion is one incompatible latest action tag
	ExclusionReason string                // ExclusionReason explains that exact incompatibility
	Path            string                // Path is the repository-relative owning file when read from disk
	Line            int                   // Line is the execution-site source line
}

// VerifyWorkflowReferences requires bounded immutable workflow and local-action references
func VerifyWorkflowReferences(ctx context.Context, root string, paths []string) (err error) {
	if ctx == nil || !validWorkflowPaths(root, paths) {
		return ErrWorkflowReferences
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return errors.Join(ErrWorkflowReferences, err)
	}
	defer func() { err = errors.Join(err, opened.Close()) }()
	localActions := newLocalActionOwner(ctx, opened, paths)
	for _, path := range paths {
		if err = ctx.Err(); err != nil {
			return errors.Join(ErrWorkflowReferences, err)
		}
		var references []WorkflowReference
		references, err = readWorkflowReferences(opened, path)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return errors.Join(ErrWorkflowReferences, err)
		}
		if _, err = localActions.expand(references); err != nil {
			return err
		}
	}
	return nil
}

func validWorkflowPaths(root string, paths []string) bool {
	if !filepath.IsAbs(root) || len(root) > MaxFuzzPathBytes || len(paths) == 0 || len(paths) > MaxRepositorySources || !slices.IsSorted(paths) {
		return false
	}
	for index, path := range paths {
		if !validWorkflowPath(path) || index > 0 && paths[index-1] == path {
			return false
		}
	}
	return true
}

func validWorkflowPath(path string) bool {
	return validFuzzText(path) && strings.HasPrefix(path, ".github/workflows/") &&
		validRelativeDirectory(filepath.FromSlash(path)) && len(path) <= MaxFuzzPathBytes && validWorkflowPathComponents(path)
}

func readWorkflowReferences(root *os.Root, path string) ([]WorkflowReference, error) {
	return readWorkflowReferencesWith(root, path, root.Open)
}

func readWorkflowReferencesWith(root *os.Root, path string, open func(string) (*os.File, error)) ([]WorkflowReference, error) {
	native := filepath.FromSlash(path)
	if err := admitRootPath(root, native, false); err != nil {
		return nil, fmt.Errorf("%s: %w", path, errors.Join(ErrWorkflowReferences, err))
	}
	file, err := open(native)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, errors.Join(ErrWorkflowReferences, err))
	}
	source, err := readBoundedSourceLimit(boundedSource{reader: file, stat: file.Stat, close: file.Close}, ErrWorkflowReferences, MaxWorkflowBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	references, err := InspectWorkflowReferences(source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for index := range references {
		references[index].Path = path
	}
	return references, nil
}

func admitRootPath(root *os.Root, relative string, directory bool) error {
	return admitRootPathWith(relative, directory, root.Lstat)
}

func admitRootPathWith(relative string, directory bool, lstat func(string) (fs.FileInfo, error)) error {
	if relative == "." {
		information, err := lstat(".")
		if err != nil {
			return err
		}
		if !validRootPathEntry(information, true, directory) {
			return ErrWorkflowReferences
		}
		return nil
	}
	current := ""
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return ErrWorkflowReferences
		}
		current = filepath.Join(current, component)
		information, err := lstat(current)
		if err != nil {
			return err
		}
		if !validRootPathEntry(information, index == len(components)-1, directory) {
			return ErrWorkflowReferences
		}
	}
	return nil
}

func validRootPathEntry(information fs.FileInfo, last, directory bool) bool {
	if information.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if !last {
		return information.IsDir()
	}
	return information.IsDir() == directory && (directory || information.Mode().IsRegular())
}

// InspectWorkflowReferences parses one bounded workflow without filesystem resolution
func InspectWorkflowReferences(source []byte) ([]WorkflowReference, error) {
	if len(source) > MaxWorkflowBytes || !utf8.Valid(source) || !validWorkflowLines(source) {
		return nil, ErrWorkflowReferences
	}
	root, err := decodeWorkflow(source)
	if err != nil {
		return nil, err
	}
	references, err := workflowReferences(root)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(references, func(left, right WorkflowReference) int {
		if left.Line != right.Line {
			return left.Line - right.Line
		}
		return strings.Compare(left.Value, right.Value)
	})
	return references, nil
}

func validWorkflowLines(source []byte) bool {
	for line := range bytes.SplitSeq(source, []byte{'\n'}) {
		if len(bytes.TrimSuffix(line, []byte{'\r'})) > MaxWorkflowLineBytes {
			return false
		}
	}
	return true
}

func decodeWorkflow(source []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, errors.Join(ErrWorkflowReferences, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.Join(ErrWorkflowReferences, err)
	}
	if !validWorkflowTree(&document) {
		return nil, ErrWorkflowReferences
	}
	if !workflowUsesAliases(&document) {
		return document.Content[0], nil
	}
	expanded, err := expandWorkflowAliases(&document, MaxWorkflowNodes)
	if err != nil {
		return nil, err
	}
	return expanded.Content[0], nil
}

func workflowUsesAliases(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode {
		return true
	}
	return slices.ContainsFunc(node.Content, workflowUsesAliases)
}

type workflowNode struct {
	value *yaml.Node
	depth int
}

func validWorkflowTree(root *yaml.Node) bool {
	pending := []workflowNode{{value: root}}
	keys := make(map[string]bool)
	nodes := 0
	for len(pending) != 0 {
		last := len(pending) - 1
		current := pending[last]
		pending = pending[:last]
		nodes++
		if nodes > MaxWorkflowNodes || current.depth > MaxWorkflowDepth || !validWorkflowNode(current.value) {
			return false
		}
		if current.value.Kind == yaml.MappingNode && !uniqueWorkflowKeys(current.value, keys) {
			return false
		}
		for _, child := range current.value.Content {
			pending = append(pending, workflowNode{value: child, depth: current.depth + 1})
		}
	}
	return true
}

func validWorkflowNode(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if !validWorkflowAlias(node) {
		return false
	}
	switch node.Kind {
	case yaml.DocumentNode:
		return node.Tag == "" && len(node.Content) == 1
	case yaml.MappingNode:
		return node.Tag == "!!map" && len(node.Content)%2 == 0
	case yaml.SequenceNode:
		return node.Tag == "!!seq"
	case yaml.ScalarNode:
		return strings.HasPrefix(node.Tag, "!!")
	case yaml.AliasNode:
		return node.Alias != nil && len(node.Content) == 0
	default:
		return false
	}
}

func validWorkflowAlias(node *yaml.Node) bool {
	return node.Kind == yaml.AliasNode || node.Alias == nil
}

type workflowExpansion struct {
	maximum int
	nodes   int
	active  map[*yaml.Node]bool
}

func expandWorkflowAliases(root *yaml.Node, maximum int) (*yaml.Node, error) {
	owner := workflowExpansion{maximum: maximum, active: make(map[*yaml.Node]bool)}
	return owner.expand(root, 0)
}

func (owner *workflowExpansion) expand(node *yaml.Node, depth int) (*yaml.Node, error) {
	if node == nil {
		return nil, ErrWorkflowReferences
	}
	if depth > MaxWorkflowDepth {
		return nil, ErrWorkflowReferences
	}
	if owner.active[node] {
		return nil, ErrWorkflowReferences
	}
	if node.Kind == yaml.AliasNode {
		owner.active[node] = true
		defer delete(owner.active, node)
		expanded, err := owner.expand(node.Alias, depth)
		if err != nil {
			return nil, err
		}
		expanded.Line = node.Line
		expanded.Column = node.Column
		expanded.HeadComment = node.HeadComment
		expanded.LineComment = node.LineComment
		expanded.FootComment = node.FootComment
		return expanded, nil
	}
	owner.nodes++
	if owner.maximum <= 0 {
		return nil, ErrWorkflowReferences
	}
	if owner.nodes > owner.maximum {
		return nil, ErrWorkflowReferences
	}
	owner.active[node] = true
	defer delete(owner.active, node)
	result := *node
	result.Anchor = ""
	result.Alias = nil
	result.Content = make([]*yaml.Node, len(node.Content))
	for index, child := range node.Content {
		expanded, err := owner.expand(child, depth+1)
		if err != nil {
			return nil, err
		}
		result.Content[index] = expanded
	}
	return &result, nil
}

func uniqueWorkflowKeys(mapping *yaml.Node, keys map[string]bool) bool {
	clear(keys)
	for index := 0; index < len(mapping.Content); index += 2 {
		key := mapping.Content[index]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || keys[key.Value] {
			return false
		}
		keys[key.Value] = true
	}
	return true
}

func workflowReferences(root *yaml.Node) ([]WorkflowReference, error) {
	if root.Kind != yaml.MappingNode {
		return nil, ErrWorkflowReferences
	}
	jobs, found := workflowField(root, "jobs")
	if !found {
		return nil, nil
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, ErrWorkflowReferences
	}
	references := make([]WorkflowReference, 0, min(len(jobs.Content)/2, MaxWorkflowReferences))
	for index := 1; index < len(jobs.Content); index += 2 {
		if err := appendJobReferences(&references, jobs.Content[index]); err != nil {
			return nil, err
		}
	}
	return references, nil
}

func appendJobReferences(references *[]WorkflowReference, job *yaml.Node) error {
	if job.Kind != yaml.MappingNode {
		return ErrWorkflowReferences
	}
	if uses, found := workflowField(job, "uses"); found {
		if err := appendWorkflowReference(references, WorkflowAction, uses); err != nil {
			return err
		}
	}
	if container, found := workflowField(job, "container"); found {
		if err := appendContainerReference(references, container); err != nil {
			return err
		}
	}
	if err := appendServiceReferences(references, job); err != nil {
		return err
	}
	return appendStepReferences(references, job)
}

func appendServiceReferences(references *[]WorkflowReference, job *yaml.Node) error {
	if services, found := workflowField(job, "services"); found {
		if services.Kind != yaml.MappingNode {
			return ErrWorkflowReferences
		}
		for index := 1; index < len(services.Content); index += 2 {
			service := services.Content[index]
			if service.Kind != yaml.MappingNode {
				return ErrWorkflowReferences
			}
			if image, found := workflowField(service, "image"); found {
				if err := appendWorkflowReference(references, WorkflowImage, image); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func appendStepReferences(references *[]WorkflowReference, job *yaml.Node) error {
	steps, found := workflowField(job, "steps")
	if !found {
		return nil
	}
	if steps.Kind != yaml.SequenceNode {
		return ErrWorkflowReferences
	}
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			return ErrWorkflowReferences
		}
		if uses, found := workflowField(step, "uses"); found {
			if err := appendWorkflowReference(references, WorkflowAction, uses); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendContainerReference(references *[]WorkflowReference, container *yaml.Node) error {
	if container.Kind == yaml.MappingNode {
		image, found := workflowField(container, "image")
		if !found {
			return ErrWorkflowReferences
		}
		return appendWorkflowReference(references, WorkflowImage, image)
	}
	return appendWorkflowReference(references, WorkflowImage, container)
}

func appendWorkflowReference(references *[]WorkflowReference, kind WorkflowReferenceKind, value *yaml.Node) error {
	if len(*references) == MaxWorkflowReferences {
		return ErrWorkflowReferences
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		return nil
	}
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
		return ErrWorkflowReferences
	}
	valid := immutableWorkflowAction(value.Value)
	if kind == WorkflowImage {
		valid = immutableWorkflowImage(value.Value)
	}
	if !valid {
		return workflowLineError(value.Line)
	}
	reference := WorkflowReference{Kind: kind, Value: value.Value, Line: value.Line}
	if err := applyWorkflowVersion(&reference, value.LineComment); err != nil {
		return workflowLineError(value.Line)
	}
	*references = append(*references, reference)
	return nil
}

func applyWorkflowVersion(reference *WorkflowReference, comment string) error {
	if reference.Kind != WorkflowAction || workflowActionRepository(reference.Value) == "" || comment == "" {
		return nil
	}
	annotation, err := parseWorkflowVersionAnnotation(comment)
	if err != nil {
		return err
	}
	reference.Version = annotation.version
	reference.ExcludedVersion = annotation.excluded
	reference.ExclusionReason = annotation.reason
	return nil
}

func workflowField(mapping *yaml.Node, name string) (*yaml.Node, bool) {
	if mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == name {
			return mapping.Content[index+1], true
		}
	}
	return nil, false
}

func immutableWorkflowAction(value string) bool {
	if strings.HasPrefix(value, "./.github/workflows/") {
		return validFuzzText(value) && validRelativeDirectory(filepath.FromSlash(strings.TrimPrefix(value, "./"))) &&
			validWorkflowPathComponents(value) && !strings.ContainsAny(value, "@\\") &&
			(strings.HasSuffix(value, ".yml") || strings.HasSuffix(value, ".yaml"))
	}
	if _, found := localActionDirectory(value); found {
		return true
	}
	if image, found := strings.CutPrefix(value, "docker://"); found {
		return immutableWorkflowImage(image)
	}
	repository, revision, found := strings.Cut(value, "@")
	return found && !strings.Contains(revision, "@") && validWorkflowRepository(repository) && lowerHex(revision, workflowCommitBytes)
}

func localActionDirectory(value string) (string, bool) {
	local, found := strings.CutPrefix(value, "./")
	if !found || len(value) > MaxFuzzPathBytes || !validFuzzText(value) || !validWorkflowPathComponents(value) || strings.ContainsAny(value, "@\\") {
		return "", false
	}
	if local == "" {
		return ".", true
	}
	return local, validRelativeDirectory(filepath.FromSlash(local))
}

func validWorkflowPathComponents(value string) bool {
	return strings.Count(filepath.ToSlash(value), "/") < MaxWorkflowPathComponents
}

func immutableWorkflowImage(value string) bool {
	image, digest, found := strings.Cut(value, "@sha256:")
	return found && validWorkflowImage(image) && !strings.Contains(digest, "@") && lowerHex(digest, workflowDigestBytes)
}

func validWorkflowImage(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !strconv.IsPrint(character) || unicode.IsSpace(character) || character == '@' {
			return false
		}
	}
	return true
}

func validWorkflowRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, character := range part {
			if !workflowRepositoryCharacter(character) {
				return false
			}
		}
	}
	return true
}

func workflowRepositoryCharacter(value rune) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' ||
		value == '_' || value == '-' || value == '.'
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func workflowLineError(line int) error {
	return fmt.Errorf("%w: line %d", ErrWorkflowReferences, line)
}
