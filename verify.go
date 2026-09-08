// Package verify executes bounded verification plans through owned process trees
package verify

import (
	"errors"
	"time"

	"github.com/secengcommons/proctree"
)

const (
	// MaxProfiles is the maximum number of profiles in one plan
	MaxProfiles = 32
	// MaxControls is the maximum number of controls in one profile
	MaxControls = 2 << 10
	// MaxPlanControls is the maximum number of controls across one plan
	MaxPlanControls = 8 << 10
	// MaxPlanBytes is the maximum caller-supplied material across one plan
	MaxPlanBytes = 64 << 20
	// MaxArguments is the maximum number of arguments in one command
	MaxArguments = 256
	// MaxArgumentBytes is the portable byte limit across one argument vector
	MaxArgumentBytes = 8 << 10
	// MaxEnvironment is the maximum number of environment entries in one command
	MaxEnvironment = 128
	// MaxEnvironmentBytes is the portable byte limit across one environment
	MaxEnvironmentBytes = 16 << 10
	// MaxPathBytes is the maximum admitted path length
	MaxPathBytes = 4 << 10
	// MaxInputBytes is the maximum standard input retained by one command
	MaxInputBytes = 1 << 20
	// MaxExpectedBytes is the combined expected-output limit
	MaxExpectedBytes = 1 << 20
	// MaxOutputBytes is the maximum capture limit for each output stream
	MaxOutputBytes = 16 << 20
	// MaxTimeout is the maximum timeout for one control
	MaxTimeout = 30 * time.Minute
)

var (
	// ErrInvalidPlan identifies rejected plan material
	ErrInvalidPlan = errors.New("invalid verification plan")
	// ErrFailed identifies a completed control which did not pass
	ErrFailed = errors.New("verification control failed")
	// ErrUnavailable identifies a control unsupported by the current environment
	ErrUnavailable = errors.New("verification control unavailable")
	// ErrCancelled identifies caller cancellation
	ErrCancelled = errors.New("verification cancelled")
	// ErrInvocation identifies command admission or process-start failure
	ErrInvocation = errors.New("verification invocation failed")
	// ErrOutput identifies exact-output disagreement
	ErrOutput = errors.New("verification output differs from its expectation")
	// ErrReporting identifies verifier output failure
	ErrReporting = errors.New("verification reporting failed")
)

// State classifies a plan or control result
type State string

const (
	// StatePass reports complete successful execution
	StatePass State = "pass"
	// StateFail reports a completed control failure
	StateFail State = "fail"
	// StateCancelled reports caller cancellation
	StateCancelled State = "cancelled"
	// StateUnavailable reports unsupported execution
	StateUnavailable State = "unavailable"
	// StateInvocationError reports admission, start or reporting failure
	StateInvocationError State = "invocation_error"
)

// Plan is an immutable verification specification after admission
type Plan struct {
	ID       string    // ID is the lowercase plan identity
	Profiles []Profile // Profiles are the selectable bounded control sets
}

// Profile is one named control sequence
type Profile struct {
	ID       string    // ID is the lowercase profile identity
	Controls []Control // Controls execute in source order until one does not pass
}

// Control binds a stable identity and display name to one command
type Control struct {
	ID      string  // ID is the lowercase control identity
	Name    string  // Name is printable display text
	Command Command // Command is copied during plan admission
}

// Command defines one directly executed process without shell construction
type Command struct {
	Executable        string        // Executable is an absolute regular file or a symlink to one
	Arguments         []string      // Arguments excludes argv[0]
	Directory         string        // Directory is repository-relative; empty selects the root
	Environment       []string      // Environment is the complete child environment
	Input             []byte        // Input is supplied to standard input
	Timeout           time.Duration // Timeout bounds process execution before process-tree cleanup begins
	OutputLimit       int           // OutputLimit applies independently to stdout and stderr
	ShowSuccessOutput bool          // ShowSuccessOutput retains safe output for passing controls
	ExpectedStdout    []byte        // ExpectedStdout is ignored when nil and exact when non-nil
	ExpectedStderr    []byte        // ExpectedStderr is ignored when nil and exact when non-nil
}

// Result records the executed prefix of one profile
type Result struct {
	Plan     string          // Plan is the admitted plan identity
	Profile  string          // Profile is the selected profile identity
	State    State           // State is the final profile state
	Controls []ControlResult // Controls contains only controls which started evaluation
	Duration time.Duration   // Duration ends after control execution and before final summary rendering
}

// ControlResult records one attempted control without retaining its output
type ControlResult struct {
	ID          string        // ID is the admitted control identity
	State       State         // State is the classified execution result
	ExitCode    int           // ExitCode is the process result supplied by Proctree
	StdoutBytes int           // StdoutBytes is the retained stdout length
	StderrBytes int           // StderrBytes is the retained stderr length
	Duration    time.Duration // Duration ends after process classification and before result rendering
}

// Validate admits and copies a plan without executing it
func Validate(root string, plan Plan) error {
	_, err := admit(root, plan)
	return err
}

// DispatchProcessOwner dispatches an internal Proctree watchdog invocation
func DispatchProcessOwner(arguments []string) (bool, int) {
	return proctree.DispatchWatchdog(arguments)
}
