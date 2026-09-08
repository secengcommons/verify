package verify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxDisplayBytes = 128
const maxIdentifierBytes = 64

type admittedPlan struct {
	id       string
	profiles []Profile
}

func admit(root string, plan Plan) (admittedPlan, error) {
	return admitWithCancellation(root, plan, func() error { return nil })
}

func admitWithCancellation(root string, plan Plan, cancelled func() error) (admittedPlan, error) {
	if !validPlanHeader(root, plan) {
		return admittedPlan{}, ErrInvalidPlan
	}
	if !validPlanAggregate(plan, MaxPlanControls, MaxPlanBytes) {
		return admittedPlan{}, ErrInvalidPlan
	}
	root = filepath.Clean(root)
	information, err := os.Stat(root)
	if err != nil || information == nil || !information.IsDir() {
		return admittedPlan{}, errors.Join(ErrInvalidPlan, err)
	}
	result := admittedPlan{id: plan.ID, profiles: make([]Profile, len(plan.Profiles))}
	seen := make(map[string]bool, len(plan.Profiles))
	executables := make(map[string]string)
	directories := map[string]string{"": root}
	for index, profile := range plan.Profiles {
		if err = cancelled(); err != nil {
			return admittedPlan{}, err
		}
		admitted, err := admitProfile(root, profile, seen, executables, directories, cancelled)
		if err != nil {
			return admittedPlan{}, err
		}
		result.profiles[index] = admitted
	}
	return result, nil
}

func validPlanHeader(root string, plan Plan) bool {
	return filepath.IsAbs(root) && len(root) <= MaxPathBytes && validIdentifier(plan.ID) &&
		len(plan.Profiles) > 0 && len(plan.Profiles) <= MaxProfiles
}

func validPlanAggregate(plan Plan, maximumControls, maximumBytes int) bool {
	if maximumControls <= 0 || maximumBytes <= 0 {
		return false
	}
	controls := 0
	bytes := len(plan.ID)
	for _, profile := range plan.Profiles {
		if len(profile.ID) > maximumBytes-bytes {
			return false
		}
		bytes += len(profile.ID)
		if len(profile.Controls) > maximumControls-controls {
			return false
		}
		controls += len(profile.Controls)
		for _, control := range profile.Controls {
			command := control.Command
			if len(command.Arguments) > MaxArguments || len(command.Environment) > MaxEnvironment {
				return false
			}
			material := len(control.ID) + len(control.Name) + len(command.Executable) + len(command.Directory) +
				len(command.Input) + len(command.ExpectedStdout) + len(command.ExpectedStderr)
			for _, value := range command.Arguments {
				material += len(value)
			}
			for _, value := range command.Environment {
				material += len(value)
			}
			if material > maximumBytes-bytes {
				return false
			}
			bytes += material
		}
	}
	return controls != 0
}

func admitProfile(
	root string,
	profile Profile,
	profiles map[string]bool,
	executables map[string]string,
	directories map[string]string,
	cancelled func() error,
) (Profile, error) {
	if !validIdentifier(profile.ID) || profiles[profile.ID] || len(profile.Controls) == 0 || len(profile.Controls) > MaxControls {
		return Profile{}, ErrInvalidPlan
	}
	profiles[profile.ID] = true
	result := Profile{ID: profile.ID, Controls: make([]Control, len(profile.Controls))}
	seen := make(map[string]bool, len(profile.Controls))
	for index, control := range profile.Controls {
		if err := cancelled(); err != nil {
			return Profile{}, err
		}
		admitted, err := admitControl(root, control, seen, executables, directories)
		if err != nil {
			return Profile{}, err
		}
		result.Controls[index] = admitted
	}
	return result, nil
}

func admitControl(root string, control Control, controls map[string]bool, executables map[string]string, directories map[string]string) (Control, error) {
	if !validIdentifier(control.ID) || controls[control.ID] || !displayText(control.Name) {
		return Control{}, ErrInvalidPlan
	}
	controls[control.ID] = true
	command, err := admitCommand(root, control.Command, executables, directories)
	if err != nil {
		return Control{}, err
	}
	return Control{ID: control.ID, Name: control.Name, Command: command}, nil
}

func admitCommand(root string, command Command, executables map[string]string, directories map[string]string) (Command, error) {
	if !validCommandBounds(command) {
		return Command{}, ErrInvalidPlan
	}
	executable, found := executables[command.Executable]
	if !found {
		var err error
		executable, err = canonicalExecutable(command.Executable)
		if err != nil {
			return Command{}, errors.Join(ErrInvalidPlan, err)
		}
		executables[command.Executable] = executable
	}
	directory, err := admittedDirectoryCached(root, command.Directory, directories)
	if err != nil {
		return Command{}, err
	}
	arguments, err := boundedStrings(command.Arguments, false)
	if err != nil {
		return Command{}, err
	}
	environment, err := boundedStrings(command.Environment, true)
	if err != nil {
		return Command{}, err
	}
	return Command{
		Executable: executable, Arguments: arguments, Directory: directory, Environment: environment,
		Input: append([]byte(nil), command.Input...), Timeout: command.Timeout, OutputLimit: command.OutputLimit,
		ShowSuccessOutput: command.ShowSuccessOutput,
		ExpectedStdout:    cloneBytes(command.ExpectedStdout), ExpectedStderr: cloneBytes(command.ExpectedStderr),
	}, nil
}

func validCommandBounds(command Command) bool {
	return validCommandPath(command) && validCommandResources(command) && validCommandExpectedOutput(command)
}

func validCommandPath(command Command) bool {
	return filepath.IsAbs(command.Executable) && command.Executable == filepath.Clean(command.Executable) && len(command.Executable) <= MaxPathBytes
}

func validCommandResources(command Command) bool {
	return command.Timeout > 0 && command.Timeout <= MaxTimeout && command.OutputLimit > 0 && command.OutputLimit <= MaxOutputBytes &&
		len(command.Arguments) <= MaxArguments && len(command.Environment) <= MaxEnvironment && len(command.Input) <= MaxInputBytes
}

func validCommandExpectedOutput(command Command) bool {
	return len(command.ExpectedStdout) <= command.OutputLimit && len(command.ExpectedStderr) <= command.OutputLimit &&
		len(command.ExpectedStderr) <= MaxExpectedBytes && len(command.ExpectedStdout) <= MaxExpectedBytes-len(command.ExpectedStderr)
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte{}, value...)
}

func canonicalExecutable(path string) (string, error) {
	return canonicalExecutablePlatform(path)
}

func canonicalExecutableWith(path string, evaluate func(string) (string, error), stat func(string) (os.FileInfo, error)) (string, error) {
	resolved, err := evaluate(path)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	information, err := stat(resolved)
	if err != nil {
		return "", err
	}
	if !information.Mode().IsRegular() || !filepath.IsAbs(resolved) || len(resolved) > MaxPathBytes {
		return "", errors.New("executable is not a regular file")
	}
	return resolved, nil
}

func admittedDirectoryCached(root, directory string, admitted map[string]string) (string, error) {
	if result, found := admitted[directory]; found {
		return result, nil
	}
	native := filepath.FromSlash(directory)
	if filepath.IsAbs(native) || native != filepath.Clean(native) || native == "." || native == ".." || strings.HasPrefix(native, ".."+string(filepath.Separator)) || len(native) > MaxPathBytes {
		return "", ErrInvalidPlan
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return "", errors.Join(ErrInvalidPlan, err)
	}
	information, statErr := opened.Stat(native)
	if err := errors.Join(statErr, opened.Close()); err != nil || information == nil || !information.IsDir() {
		return "", errors.Join(ErrInvalidPlan, err)
	}
	result := filepath.Join(root, native)
	admitted[directory] = result
	return result, nil
}

func boundedStrings(values []string, environment bool) ([]string, error) {
	result := make([]string, len(values))
	var environmentNames [MaxEnvironment]string
	environmentCount := 0
	maximum := MaxArgumentBytes
	if environment {
		maximum = MaxEnvironmentBytes
	}
	total := 0
	for index, value := range values {
		if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return nil, ErrInvalidPlan
		}
		if len(value) > maximum-total {
			return nil, ErrInvalidPlan
		}
		total += len(value)
		if environment {
			name, _, found := strings.Cut(value, "=")
			if !found || !validEnvironmentName(name) || duplicateEnvironmentName(environmentNames[:environmentCount], name) {
				return nil, ErrInvalidPlan
			}
			environmentNames[environmentCount] = name
			environmentCount++
		}
		result[index] = value
	}
	return result, nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxIdentifierBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' && character != '-' {
					return false
				}
			}
		}
	}
	return true
}

func validEnvironmentName(value string) bool {
	if value == "" || !environmentNameStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !environmentNamePart(value[index]) {
			return false
		}
	}
	return true
}

func environmentNameStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func environmentNamePart(value byte) bool {
	return environmentNameStart(value) || value >= '0' && value <= '9'
}

func duplicateEnvironmentName(previous []string, name string) bool {
	for _, value := range previous {
		if strings.EqualFold(value, name) {
			return true
		}
	}
	return false
}

func displayText(value string) bool {
	if value == "" || len(value) > maxDisplayBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !strconv.IsPrint(character) {
			return false
		}
	}
	return true
}

func selectedProfile(plan admittedPlan, id string) (Profile, error) {
	for _, profile := range plan.profiles {
		if profile.ID == id {
			return profile, nil
		}
	}
	return Profile{}, fmt.Errorf("%w: unknown profile %q", ErrInvalidPlan, id)
}
