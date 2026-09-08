package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
	verify "github.com/secengcommons/verify"
)

func TestIdentityText(t *testing.T) {
	t.Parallel()
	identity := validIdentityFixture()
	if value := identityText(identity); !strings.HasPrefix(value, "secverify source=") {
		t.Fatalf("development identity = %q", value)
	}
	identity.version = "0.1.0"
	if value := identityText(identity); !strings.HasPrefix(value, "secverify 0.1.0 source=") {
		t.Fatalf("release identity = %q", value)
	}
	identity.version = ""
	if validExecutableIdentity(identity) {
		t.Fatal("empty version accepted")
	}
	identity = validIdentityFixture()
	identity.source = "invalid\nsource"
	if validExecutableIdentity(identity) {
		t.Fatal("control character accepted")
	}
	identity.source = "invalid\u202esource"
	if validExecutableIdentity(identity) {
		t.Fatal("format character accepted")
	}
	if err := writeExecutionIdentity(nil, validIdentityFixture()); !errors.Is(err, verify.ErrInvocation) {
		t.Fatalf("nil identity output error = %v", err)
	}
}

func TestExecuteVerification(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	plan := verify.Plan{ID: "plan", Profiles: []verify.Profile{{ID: "test", Controls: []verify.Control{{
		ID: "command", Name: "Command", Command: verify.Command{
			Executable: executable, Arguments: []string{"-test.run=^$"}, Environment: selectedEnvironment(), Timeout: time.Minute, OutputLimit: 1 << 20,
		},
	}}}}}
	var stdout, stderr bytes.Buffer
	if code := executeVerification(t.Context(), root, plan, "test", &stdout, &stderr); code != exitPass || stderr.Len() != 0 {
		t.Fatalf("verification = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
	plan.Profiles[0].Controls[0].Command.ExpectedStdout = []byte("unexpected")
	stdout.Reset()
	if code := executeVerification(t.Context(), root, plan, "test", &stdout, &stderr); code != exitFail || !strings.Contains(stderr.String(), "unexpected output") {
		t.Fatalf("failed verification = (%d, %q, %q)", code, stdout.String(), stderr.String())
	}
	plan.Profiles[0].Controls[0].Command.ExpectedStdout = nil
	if code := executeVerification(nilContext(), root, plan, "test", io.Discard, io.Discard); code != exitInvocation {
		t.Fatalf("nil context exit = %d", code)
	}
	if code := executeVerification(t.Context(), root, verify.Plan{}, "test", io.Discard, io.Discard); code != exitInvocation {
		t.Fatalf("invalid plan exit = %d", code)
	}
	if err := writeExecutionIdentity(errorWriter{}, validIdentityFixture()); err == nil {
		t.Fatal("identity writer failure was accepted")
	}
}

func TestReportExecutionErrorClasses(t *testing.T) {
	for _, test := range []struct {
		name   string
		state  verify.State
		err    error
		action string
		code   int
	}{
		{name: "failure", state: verify.StateFail, err: verify.ErrFailed, action: "failed", code: exitFail},
		{name: "report", state: verify.StateInvocationError, err: errors.Join(verify.ErrInvocation, verify.ErrReporting), action: "could not write output", code: exitInvocation},
		{name: "report unavailable", state: verify.StateInvocationError, err: errors.Join(verify.ErrReporting, verify.ErrUnavailable), action: "could not write output", code: exitInvocation},
		{name: "report cancelled", state: verify.StateInvocationError, err: errors.Join(verify.ErrReporting, verify.ErrCancelled), action: "could not write output", code: exitInvocation},
		{name: "cleanup", state: verify.StateFail, err: errors.Join(verify.ErrFailed, verify.ErrUnavailable, verify.ErrCancelled, proctree.ErrCleanup), action: "cleanup failed", code: exitFail},
		{name: "timeout", state: verify.StateFail, err: errors.Join(verify.ErrFailed, context.DeadlineExceeded), action: "timed out", code: exitFail},
		{name: "output", state: verify.StateFail, err: errors.Join(verify.ErrFailed, verify.ErrOutput), action: "produced unexpected output", code: exitFail},
		{name: "cancelled", state: verify.StateCancelled, err: verify.ErrCancelled, action: "cancelled", code: exitCancelled},
		{name: "unavailable", state: verify.StateUnavailable, err: verify.ErrUnavailable, action: "unavailable", code: exitUnavailable},
		{name: "invocation", state: verify.StateInvocationError, err: verify.ErrInvocation, action: "could not start", code: exitInvocation},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := verify.Result{Profile: "all", State: test.state, Controls: []verify.ControlResult{{ID: "control", State: test.state}}}
			var output bytes.Buffer
			if code := reportExecutionError(&output, result, test.err); code != test.code || output.String() != "secverify: all "+test.action+" at control\n" {
				t.Fatalf("report = (%d, %q)", code, output.String())
			}
		})
	}
	result := verify.Result{Profile: "all", State: verify.StateInvocationError, Controls: []verify.ControlResult{{ID: "passed", State: verify.StatePass}}}
	var output bytes.Buffer
	if code := reportExecutionError(&output, result, errors.Join(verify.ErrInvocation, verify.ErrReporting)); code != exitInvocation ||
		output.String() != "secverify: all could not write output after passed\n" {
		t.Fatalf("post-control report = (%d, %q)", code, output.String())
	}
	if code := reportExecutionError(errorWriter{}, result, verify.ErrFailed); code != exitInvocation {
		t.Fatalf("writer failure exit = %d", code)
	}
	if location := executionLocation(verify.Result{}, verify.ErrFailed); location != "" {
		t.Fatalf("empty location = %q", location)
	}
}

func validIdentityFixture() executableIdentity {
	return executableIdentity{
		version: developmentVersion, source: "commit:" + strings.Repeat("a", gitCommitHexLength),
		goVersion: "go1.26.6", platform: "windows/amd64",
	}
}
