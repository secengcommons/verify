package goverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/secengcommons/proctree"
)

var ErrDependencyCurrency = errors.New("go dependency update available")

type dependencyModule struct {
	Path      string
	Version   string
	Main      bool
	Indirect  bool
	Retracted []string
	Replace   *dependencyReplacement
	Update    *struct {
		Path    string
		Version string
	}
}

type dependencyReplacement struct {
	Path    string
	Version string
	Dir     string
}

// CheckModuleCurrency requires the selected module dependency graph to have no applicable update
func CheckModuleCurrency(ctx context.Context, root string, tool Tool, module Module) error {
	if !validRepositoryTools(module.Tools) {
		return ErrDependencyCurrency
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrDependencyCurrency, err)
		}
	}
	return checkModuleCurrencyWith(ctx, root, tool, module, proctree.Run)
}

func checkModuleCurrencyWith(ctx context.Context, root string, tool Tool, module Module, runner repositoryModuleRunner) error {
	tool.Environment = ReplaceEnvironment(tool.Environment, "GOFLAGS", "-mod=readonly")
	result, err := runRepositoryGo(ctx, root, module.Directory, tool, runner, "list", "-m", "-u", "-json", "all")
	if err != nil {
		return errors.Join(ErrDependencyCurrency, err)
	}
	modules, err := decodeDependencyModules(result.Stdout)
	if err != nil {
		return err
	}
	toolOwners, err := dependencyToolOwners(modules, module.Tools)
	if err != nil {
		return err
	}
	if err = requireCurrentDependencies(root, modules, toolOwners); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDependencyCurrency, err)
	}
	return nil
}

func requireCurrentDependencies(root string, modules []dependencyModule, toolOwners map[string]bool) error {
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return errors.Join(ErrDependencyCurrency, err)
	}
	for _, dependency := range modules {
		if dependency.Main || dependency.Indirect && !toolOwners[dependency.Path] {
			continue
		}
		sourceOwned, ownershipErr := sourceOwnedDependency(canonicalRoot, dependency)
		if ownershipErr != nil {
			return ownershipErr
		}
		if sourceOwned {
			continue
		}
		if len(dependency.Retracted) != 0 {
			return fmt.Errorf("%w: %s %s is retracted", ErrDependencyCurrency, dependency.Path, dependency.Version)
		}
		if dependency.Update == nil {
			continue
		}
		return fmt.Errorf("%w: %s %s to %s", ErrDependencyCurrency, dependency.Path, dependency.Version, dependency.Update.Version)
	}
	return nil
}

func decodeDependencyModules(source []byte) ([]dependencyModule, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	modules := make([]dependencyModule, 0)
	seen := make(map[string]bool)
	mainModules := 0
	for {
		var module dependencyModule
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !validDependencyModule(module) || seen[module.Path] {
			return nil, errors.Join(ErrDependencyCurrency, err)
		}
		seen[module.Path] = true
		if module.Main {
			mainModules++
		}
		modules = append(modules, module)
	}
	if len(modules) == 0 || mainModules != 1 {
		return nil, ErrDependencyCurrency
	}
	return modules, nil
}

func validDependencyModule(module dependencyModule) bool {
	if !validFuzzText(module.Path) || len(module.Path) > MaxFuzzPathBytes || !module.Main && !validFuzzText(module.Version) {
		return false
	}
	return validDependencyReplacement(module.Replace) &&
		(module.Update == nil || module.Update.Path == module.Path && validFuzzText(module.Update.Version))
}

func validDependencyReplacement(replacement *dependencyReplacement) bool {
	if replacement == nil {
		return true
	}
	return replacement.Path != "" && validFuzzText(replacement.Path) && len(replacement.Path) <= MaxFuzzPathBytes &&
		(replacement.Version == "" || validFuzzText(replacement.Version)) &&
		replacement.Dir != "" && filepath.IsAbs(replacement.Dir) && validFuzzText(replacement.Dir) && len(replacement.Dir) <= MaxFuzzPathBytes
}

func sourceOwnedDependency(root string, module dependencyModule) (bool, error) {
	if module.Replace == nil || module.Replace.Version != "" {
		return false, nil
	}
	directory, err := filepath.EvalSymlinks(module.Replace.Dir)
	if err != nil {
		return false, errors.Join(ErrDependencyCurrency, err)
	}
	relative, err := filepath.Rel(root, directory)
	if err != nil || !validRelativeDirectory(relative) {
		return false, errors.Join(ErrDependencyCurrency, err)
	}
	return true, nil
}

func dependencyToolOwners(modules []dependencyModule, tools []string) (map[string]bool, error) {
	owners := make(map[string]bool, len(tools))
	for _, tool := range tools {
		owner := ""
		for _, module := range modules {
			if (tool == module.Path || strings.HasPrefix(tool, module.Path+"/")) && len(module.Path) > len(owner) {
				owner = module.Path
			}
		}
		if owner == "" {
			return nil, ErrDependencyCurrency
		}
		owners[owner] = true
	}
	return owners, nil
}
