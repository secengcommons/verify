package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
	"github.com/secengcommons/verify/internal/repositoryop"
)

type repositoryOperation uint8

const (
	repositoryCoverageSelfTest repositoryOperation = iota
	repositoryFuzzInventory
	repositoryFuzzCampaign
	repositoryCoverage
	repositoryWorkflowAdmission
	repositoryWorkflowDependencies
	repositoryModuleCurrency
	repositoryCompile
	repositoryBenchmark
)

func classifyRepositoryOperation(arguments []string) (repositoryOperation, bool) {
	if len(arguments) != 1 {
		return 0, false
	}
	switch arguments[0] {
	case "__go-coverage-self-test":
		return repositoryCoverageSelfTest, true
	case "__go-fuzz-inventory":
		return repositoryFuzzInventory, true
	case "__go-fuzz-campaign":
		return repositoryFuzzCampaign, true
	case "__go-workflow-admission":
		return repositoryWorkflowAdmission, true
	case "__go-workflow-dependencies":
		return repositoryWorkflowDependencies, true
	case "__go-module-currency":
		return repositoryModuleCurrency, true
	case "__go-benchmark":
		return repositoryBenchmark, true
	default:
		if validRepositoryOperationIndex(arguments[0], "__go-compile") {
			return repositoryCompile, true
		}
		if validRepositoryOperationIndex(arguments[0], "__go-coverage") {
			return repositoryCoverage, true
		}
		return 0, false
	}
}

func validRepositoryOperationIndex(argument, operation string) bool {
	value, found := strings.CutPrefix(argument, operation+":")
	if !found || value == "" {
		return false
	}
	index, err := strconv.Atoi(value)
	return err == nil && strconv.Itoa(index) == value
}

func runRepositoryOperation(
	ctx context.Context,
	root string,
	operation repositoryOperation,
	argument string,
	input io.Reader,
	output io.Writer,
) error {
	switch operation {
	case repositoryCoverageSelfTest:
		return runCoverageSelfTestOperation(input, argument)
	case repositoryFuzzInventory:
		return runFuzzInventorySpecification(ctx, input, argument, output)
	case repositoryFuzzCampaign:
		return runFuzzCampaignSpecification(ctx, root, input, argument, output)
	case repositoryCoverage:
		return runCoverageSpecification(ctx, root, input, argument, output)
	case repositoryWorkflowAdmission:
		return runWorkflowAdmissionSpecification(ctx, root, input, argument)
	case repositoryWorkflowDependencies:
		return runWorkflowDependencySpecification(ctx, root, input, argument)
	case repositoryModuleCurrency:
		return runModuleCurrencySpecification(ctx, root, input, argument)
	case repositoryCompile:
		return runCompileSpecification(ctx, root, input, argument, output)
	case repositoryBenchmark:
		return runBenchmarkSpecification(ctx, root, input, argument, output)
	default:
		return verify.ErrInvocation
	}
}

func runCoverageSelfTestOperation(input io.Reader, operation string) error {
	if err := decodeRepositoryOperation(input, operation, &repositoryop.Specification[struct{}, struct{}]{}); err != nil {
		return err
	}
	return runCoverageSelfTest()
}

func runFuzzInventorySpecification(ctx context.Context, input io.Reader, operation string, output io.Writer) error {
	var specification repositoryop.Specification[struct{}, []goverify.FuzzTarget]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.WriteFuzzInventory(ctx, specification.Material, output)
}

func runFuzzCampaignSpecification(ctx context.Context, root string, input io.Reader, operation string, output io.Writer) error {
	var specification repositoryop.Specification[goverify.Campaign, []goverify.FuzzTarget]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.RunFuzzCampaign(ctx, root, specification.Owner, specification.Material, output)
}

func runCoverageSpecification(ctx context.Context, root string, input io.Reader, operation string, output io.Writer) error {
	var specification repositoryop.Specification[goverify.Tool, goverify.TestScope]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.RunCoverage(ctx, root, specification.Owner, specification.Material, output)
}

func runWorkflowAdmissionSpecification(ctx context.Context, root string, input io.Reader, operation string) error {
	var specification repositoryop.Specification[struct{}, []string]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.VerifyWorkflowReferences(ctx, root, specification.Material)
}

func runWorkflowDependencySpecification(ctx context.Context, root string, input io.Reader, operation string) error {
	var specification repositoryop.Specification[goverify.Tool, []string]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.VerifyWorkflowCurrency(ctx, root, specification.Material, specification.Owner)
}

func runModuleCurrencySpecification(ctx context.Context, root string, input io.Reader, operation string) error {
	var specification repositoryop.Specification[goverify.Tool, []goverify.Module]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return runModuleCurrencyOperation(ctx, root, specification.Owner, specification.Material)
}

func runCompileSpecification(ctx context.Context, root string, input io.Reader, operation string, output io.Writer) error {
	var specification repositoryop.Specification[goverify.Tool, goverify.Module]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.CompileModule(ctx, root, specification.Owner, specification.Material, output)
}

func runBenchmarkSpecification(ctx context.Context, root string, input io.Reader, operation string, output io.Writer) error {
	var specification repositoryop.Specification[goverify.Tool, []goverify.BenchmarkTarget]
	if err := decodeRepositoryOperation(input, operation, &specification); err != nil {
		return err
	}
	return goverify.RunBenchmarks(ctx, root, specification.Owner, specification.Material, output)
}

func decodeRepositoryOperation(input io.Reader, operation string, specification any) error {
	if err := repositoryop.Decode(input, operation, specification); err != nil {
		return errors.Join(verify.ErrInvalidPlan, err)
	}
	return nil
}

func runModuleCurrencyOperation(ctx context.Context, root string, tool goverify.Tool, modules []goverify.Module) error {
	for _, module := range modules {
		if err := goverify.CheckModuleCurrency(ctx, root, tool, module); err != nil {
			return fmt.Errorf("%s: %w", module.Name, err)
		}
	}
	return nil
}

func runCoverageSelfTest() error {
	return runCoverageSelfTestWith(goverify.CheckCoverage)
}

func runCoverageSelfTestWith(check func(io.Reader) (goverify.Coverage, error)) error {
	profiles := []struct {
		value string
		want  error
	}{
		{value: "mode: atomic\nself.test/value.go:1.1,1.2 1 0\n", want: goverify.ErrIncompleteCoverage},
		{value: "mode: count\nself.test/value.go:1.1,1.2 1 1\n", want: goverify.ErrCoverageProfile},
	}
	for _, profile := range profiles {
		if _, err := check(strings.NewReader(profile.value)); !errors.Is(err, profile.want) {
			return errors.New("coverage self-test accepted invalid material")
		}
	}
	if _, err := check(strings.NewReader("mode: atomic\nself.test/value.go:1.1,1.2 1 1\n")); err != nil {
		return errors.Join(errors.New("coverage self-test rejected complete material"), err)
	}
	return nil
}
