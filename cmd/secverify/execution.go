package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/internal/exactwrite"
	"github.com/secengcommons/verify/internal/safeoutput"
)

const exitPass = 0
const exitFail = 1
const exitInvocation = 2
const exitUnavailable = 3
const exitCancelled = 4

func writeExecutionIdentity(output io.Writer, identity executableIdentity) error {
	if output == nil || !validExecutableIdentity(identity) {
		return verify.ErrInvocation
	}
	return exactwrite.Bytes(output, []byte(identityText(identity)))
}

func executeVerification(ctx context.Context, root string, plan verify.Plan, profile string, stdout, stderr io.Writer) int {
	result, err := verify.Execute(ctx, root, plan, profile, stdout)
	if err == nil {
		return exitPass
	}
	if len(result.Controls) != 0 || errors.Is(err, verify.ErrReporting) {
		return reportExecutionError(stderr, result, err)
	}
	return writeFailure(stderr, err)
}

func validExecutableIdentity(identity executableIdentity) bool {
	return displayIdentityText(identity.version) && displayIdentityText(identity.source) &&
		displayIdentityText(identity.goVersion) && displayIdentityText(identity.platform)
}

func displayIdentityText(value string) bool {
	if value == "" || len(value) > maxIdentityTextBytes {
		return false
	}
	for _, character := range value {
		if !strconv.IsPrint(character) {
			return false
		}
	}
	return true
}

func identityText(identity executableIdentity) string {
	name := "secverify"
	if identity.version != developmentVersion {
		name += " " + identity.version
	}
	return fmt.Sprintf("%s source=%s go=%s platform=%s\n", name, identity.source, identity.goVersion, identity.platform)
}

func reportExecutionError(stderr io.Writer, result verify.Result, err error) int {
	action := "failed"
	switch {
	case errors.Is(err, verify.ErrReporting):
		action = "could not write output"
	case errors.Is(err, proctree.ErrCleanup):
		action = "cleanup failed"
	case result.State == verify.StateCancelled:
		action = "cancelled"
	case result.State == verify.StateUnavailable:
		action = "unavailable"
	case result.State == verify.StateInvocationError:
		action = "could not start"
	case errors.Is(err, context.DeadlineExceeded):
		action = "timed out"
	case errors.Is(err, verify.ErrOutput):
		action = "produced unexpected output"
	}
	location := executionLocation(result, err)
	message := fmt.Sprintf("secverify: %s %s%s\n", result.Profile, action, location)
	if writeErr := exactwrite.Bytes(stderr, []byte(message)); writeErr != nil {
		return exitInvocation
	}
	if errors.Is(err, verify.ErrReporting) {
		return exitInvocation
	}
	return exitFor(err)
}

func executionLocation(result verify.Result, err error) string {
	if len(result.Controls) == 0 {
		return ""
	}
	last := result.Controls[len(result.Controls)-1]
	if last.State == result.State {
		return " at " + last.ID
	}
	if errors.Is(err, verify.ErrReporting) {
		return " after " + last.ID
	}
	return ""
}

func exitFor(err error) int {
	switch {
	case errors.Is(err, proctree.ErrCleanup):
		return exitFail
	case errors.Is(err, verify.ErrUnavailable):
		return exitUnavailable
	case errors.Is(err, verify.ErrCancelled), errors.Is(err, context.Canceled):
		return exitCancelled
	case errors.Is(err, verify.ErrInvocation), errors.Is(err, verify.ErrInvalidPlan):
		return exitInvocation
	default:
		return exitFail
	}
}

func writeFailure(stderr io.Writer, err error) int {
	code := exitFor(err)
	if writeErr := exactwrite.Bytes(stderr, []byte("secverify: "+safeoutput.Diagnostic(err.Error())+"\n")); writeErr != nil {
		return exitInvocation
	}
	return code
}
