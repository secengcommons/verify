package goverify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

const maxWorkflowExclusionReasonBytes = 256
const actionVersionComponents = 3

var ErrWorkflowCurrency = errors.New("workflow dependency update available")

type workflowVersionAnnotation struct {
	version  string
	excluded string
	reason   string
}

type actionVersion struct {
	value      string
	ends       [actionVersionComponents]uint32
	components uint8
}

type actionTag struct {
	name    string
	version actionVersion
	commit  string
	base    bool
	peeled  bool
}

type workflowCurrencyRun func(context.Context, proctree.Command) (proctree.Result, error)

// VerifyWorkflowCurrency requires every remote action pin to use the highest compatible stable tag
func VerifyWorkflowCurrency(ctx context.Context, root string, paths []string, git Tool) error {
	return verifyWorkflowCurrencyWith(ctx, root, paths, git, proctree.Run)
}

func verifyWorkflowCurrencyWith(ctx context.Context, root string, paths []string, git Tool, runner workflowCurrencyRun) error {
	git.Environment = append([]string(nil), git.Environment...)
	if ctx == nil || runner == nil || !validWorkflowPaths(root, paths) || !validWorkflowGit(root, git) {
		return ErrWorkflowCurrency
	}
	dependencies, err := readWorkflowDependencies(ctx, root, paths)
	if err != nil {
		return err
	}
	repositories := make([]string, 0, len(dependencies))
	for repository := range dependencies {
		repositories = append(repositories, repository)
	}
	slices.Sort(repositories)
	for _, repository := range repositories {
		tags, resolveErr := resolveActionTags(ctx, root, repository, git, runner)
		if resolveErr != nil {
			return resolveErr
		}
		for _, reference := range dependencies[repository] {
			if err = verifyActionReference(reference, tags); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrWorkflowCurrency, err)
	}
	return nil
}

func validWorkflowGit(root string, git Tool) bool {
	plan := verify.Plan{ID: "workflow_currency", Profiles: []verify.Profile{{
		ID: "workflow_currency", Controls: []verify.Control{{
			ID: "git", Name: "Git", Command: verify.Command{
				Executable: git.Executable, Environment: git.Environment, Timeout: git.Timeout, OutputLimit: git.OutputLimit,
			},
		}},
	}}}
	return verify.Validate(root, plan) == nil
}

func readWorkflowDependencies(ctx context.Context, root string, paths []string) (map[string][]WorkflowReference, error) {
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.Join(ErrWorkflowCurrency, err)
	}
	dependencies := make(map[string][]WorkflowReference)
	localActions := newLocalActionOwner(ctx, opened, paths)
	for _, path := range paths {
		if err = ctx.Err(); err != nil {
			return nil, errors.Join(ErrWorkflowCurrency, err, opened.Close())
		}
		references, readErr := readWorkflowReferences(opened, path)
		if readErr != nil {
			return nil, errors.Join(ErrWorkflowCurrency, readErr, opened.Close())
		}
		references, err = localActions.expand(references)
		if err != nil {
			return nil, errors.Join(ErrWorkflowCurrency, err, opened.Close())
		}
		addWorkflowDependencies(dependencies, references)
	}
	return dependencies, workflowCurrencyClose(opened.Close())
}

func addWorkflowDependencies(dependencies map[string][]WorkflowReference, references []WorkflowReference) {
	for _, reference := range references {
		repository := workflowActionRepository(reference.Value)
		if repository != "" {
			dependencies[repository] = append(dependencies[repository], reference)
		}
	}
}

func workflowCurrencyClose(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrWorkflowCurrency, err)
}

func resolveActionTags(ctx context.Context, root, repository string, git Tool, runner workflowCurrencyRun) (map[string]actionTag, error) {
	result, runErr := runner(ctx, proctree.Command{
		Executable:  git.Executable,
		Arguments:   []string{"--git-dir=" + os.DevNull, "-c", "credential.helper=", "ls-remote", "--tags", "https://github.com/" + repository + ".git"},
		Directory:   root,
		Environment: git.Environment,
		StdoutLimit: min(git.OutputLimit, MaxRepositoryCommandBytes),
		StderrLimit: min(git.OutputLimit, MaxRepositoryCommandBytes),
		Timeout:     git.Timeout,
	})
	if runErr != nil || !result.Started || result.ExitCode != 0 || result.Outcome != proctree.OutcomeCompleted {
		return nil, errors.Join(fmt.Errorf("%w: resolve %s", ErrWorkflowCurrency, repository), runErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrWorkflowCurrency, err)
	}
	tags, err := parseActionTags(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, repository)
	}
	return tags, nil
}

func parseActionTags(source []byte) (map[string]actionTag, error) {
	tags := make(map[string]actionTag)
	for line := range strings.SplitSeq(string(source), "\n") {
		if len(line) == 0 {
			continue
		}
		if err := addActionTag(tags, line); err != nil {
			return nil, err
		}
	}
	for _, tag := range tags {
		if !tag.base {
			return nil, ErrWorkflowCurrency
		}
	}
	if len(tags) == 0 {
		return nil, ErrWorkflowCurrency
	}
	return tags, nil
}

func addActionTag(tags map[string]actionTag, line string) error {
	separator := strings.IndexByte(line, '\t')
	if separator != workflowCommitBytes || strings.IndexByte(line[separator+1:], '\t') >= 0 || !lowerHex(line[:separator], workflowCommitBytes) {
		return ErrWorkflowCurrency
	}
	name, peeled, found := actionTagName(line[separator+1:])
	if !found {
		return nil
	}
	version, valid := parseActionVersion(name)
	if !valid {
		return nil
	}
	tag := tags[name]
	if peeled {
		if tag.peeled {
			return ErrWorkflowCurrency
		}
		tag.peeled = true
		tag.commit = line[:separator]
	} else {
		if tag.base {
			return ErrWorkflowCurrency
		}
		tag.base = true
		if !tag.peeled {
			tag.commit = line[:separator]
		}
	}
	tag.version = version
	tags[name] = tag
	return nil
}

func actionTagName(reference string) (string, bool, bool) {
	name, found := strings.CutPrefix(reference, "refs/tags/")
	if !found || name == "" {
		return "", false, false
	}
	if peeled, found := strings.CutSuffix(name, "^{}"); found {
		return peeled, true, peeled != ""
	}
	return name, false, true
}

func verifyActionReference(reference WorkflowReference, tags map[string]actionTag) error {
	current, found := tags[reference.Version]
	if !found || current.commit != workflowActionRevision(reference.Value) {
		return workflowCurrencyError(reference)
	}
	latest := latestActionTag(tags)
	comparison := compareActionVersion(current.version, latest.version)
	if comparison == 0 {
		if reference.Version != latest.name || reference.ExcludedVersion != "" {
			return workflowCurrencyError(reference)
		}
		return nil
	}
	if reference.ExcludedVersion != latest.name || !validFuzzText(reference.ExclusionReason) {
		return workflowCurrencyError(reference)
	}
	remaining := latestActionTagBelow(tags, latest.version)
	if remaining.name == "" || reference.Version != remaining.name {
		return workflowCurrencyError(reference)
	}
	return nil
}

func latestActionTag(tags map[string]actionTag) actionTag {
	return selectLatestActionTag(tags, nil)
}

func latestActionTagBelow(tags map[string]actionTag, excluded actionVersion) actionTag {
	return selectLatestActionTag(tags, &excluded)
}

func selectLatestActionTag(tags map[string]actionTag, excluded *actionVersion) actionTag {
	var latest actionTag
	for name, tag := range tags {
		if excluded != nil && compareActionVersion(tag.version, *excluded) == 0 {
			continue
		}
		comparison := compareActionVersion(tag.version, latest.version)
		if latest.name == "" || comparison > 0 || comparison == 0 && tag.version.components > latest.version.components {
			latest = tag
			latest.name = name
		}
	}
	return latest
}

func parseWorkflowVersionAnnotation(value string) (workflowVersionAnnotation, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSpace(strings.TrimPrefix(value, "#"))
	version, remainder, excluded := strings.Cut(value, "; exclude ")
	if _, valid := parseActionVersion(version); !valid {
		return workflowVersionAnnotation{}, ErrWorkflowCurrency
	}
	result := workflowVersionAnnotation{version: version}
	if !excluded {
		return result, nil
	}
	excludedVersion, reason, found := strings.Cut(remainder, ": ")
	if !found || len(reason) > maxWorkflowExclusionReasonBytes || !validFuzzText(reason) {
		return workflowVersionAnnotation{}, ErrWorkflowCurrency
	}
	if _, valid := parseActionVersion(excludedVersion); !valid {
		return workflowVersionAnnotation{}, ErrWorkflowCurrency
	}
	result.excluded = excludedVersion
	result.reason = reason
	return result, nil
}

func parseActionVersion(value string) (actionVersion, bool) {
	result := actionVersion{value: value}
	if len(value) < 2 || value[0] != 'v' {
		return actionVersion{}, false
	}
	component := 0
	start := 1
	for index := 1; index <= len(value); index++ {
		if index != len(value) && value[index] != '.' {
			continue
		}
		if component == len(result.ends) || !validActionVersionComponent(value[start:index]) {
			return actionVersion{}, false
		}
		result.ends[component] = uint32(index)
		component++
		start = index + 1
	}
	result.components = uint8(component)
	return result, true
}

func validActionVersionComponent(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareActionVersion(left, right actionVersion) int {
	for component := range actionVersionComponents {
		if compared := compareVersionComponent(left.component(component), right.component(component)); compared != 0 {
			return compared
		}
	}
	return 0
}

func (version actionVersion) component(index int) string {
	if index >= int(version.components) {
		return "0"
	}
	start := 1
	if index != 0 {
		start = int(version.ends[index-1]) + 1
	}
	return version.value[start:version.ends[index]]
}

func compareVersionComponent(left, right string) int {
	if len(left) != len(right) {
		return len(left) - len(right)
	}
	return strings.Compare(left, right)
}

func workflowActionRepository(value string) string {
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
		return ""
	}
	repository, _, found := strings.Cut(value, "@")
	if !found {
		return ""
	}
	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func workflowActionRevision(value string) string {
	_, revision, _ := strings.Cut(value, "@")
	return revision
}

func workflowCurrencyError(reference WorkflowReference) error {
	if reference.Path != "" {
		return fmt.Errorf("%w: %s:%d: %s", ErrWorkflowCurrency, reference.Path, reference.Line, reference.Value)
	}
	return fmt.Errorf("%w: line %d: %s", ErrWorkflowCurrency, reference.Line, reference.Value)
}
