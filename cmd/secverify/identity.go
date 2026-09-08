package main

import (
	"runtime"
	"runtime/debug"
	"strings"
)

const unavailableSource = "unavailable"
const gitCommitHexLength = 40
const gitSHA256HexLength = 64
const maxIdentityTextBytes = 128

type executableIdentity struct {
	version   string
	source    string
	goVersion string
	platform  string
}

func currentIdentity() executableIdentity {
	information, available := debug.ReadBuildInfo()
	return identityFromBuild(executableVersion(information, available), information, available)
}

func identityFromBuild(version string, information *debug.BuildInfo, available bool) executableIdentity {
	identity := executableIdentity{
		version: version, source: unavailableSource, goVersion: runtime.Version(),
		platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	if available && information != nil {
		identity.source = sourceIdentity(information.Settings)
	}
	return identity
}

type sourceMetadata struct {
	vcs          string
	revision     string
	modified     bool
	seenVCS      bool
	seenRevision bool
	seenModified bool
}

func sourceIdentity(settings []debug.BuildSetting) string {
	var metadata sourceMetadata
	for _, setting := range settings {
		if !metadata.add(setting) {
			return unavailableSource
		}
	}
	if metadata.vcs != "git" || !gitObjectID(metadata.revision) || !metadata.seenModified {
		return unavailableSource
	}
	if metadata.modified {
		return "dirty:" + metadata.revision
	}
	return "commit:" + metadata.revision
}

func (metadata *sourceMetadata) add(setting debug.BuildSetting) bool {
	switch setting.Key {
	case "vcs":
		if metadata.seenVCS {
			return false
		}
		metadata.seenVCS = true
		metadata.vcs = setting.Value
	case "vcs.revision":
		if metadata.seenRevision {
			return false
		}
		metadata.seenRevision = true
		metadata.revision = setting.Value
	case "vcs.modified":
		if metadata.seenModified || setting.Value != "true" && setting.Value != "false" {
			return false
		}
		metadata.seenModified = true
		metadata.modified = setting.Value == "true"
	}
	return true
}

func gitObjectID(value string) bool {
	if len(value) != gitCommitHexLength && len(value) != gitSHA256HexLength {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func executableVersion(information *debug.BuildInfo, available bool) string {
	if !available || information == nil || information.Main.Path != verifyModule || !releasedVersion(information.Main.Version) ||
		!unreplacedBuild(information) ||
		!releasedDependency(information, cliModule, qualifiedCLIVersion) ||
		!releasedDependency(information, proctreeModule, qualifiedProctreeVersion) ||
		!releasedDependency(information, yamlModule, qualifiedYAMLVersion) {
		return developmentVersion
	}
	return strings.TrimPrefix(information.Main.Version, "v")
}

func unreplacedBuild(information *debug.BuildInfo) bool {
	if information.Main.Replace != nil {
		return false
	}
	for _, dependency := range information.Deps {
		if dependency != nil && dependency.Replace != nil {
			return false
		}
	}
	return true
}

func releasedDependency(information *debug.BuildInfo, path, version string) bool {
	found := false
	for _, dependency := range information.Deps {
		if dependency == nil || dependency.Path != path {
			continue
		}
		if found || dependency.Version != version {
			return false
		}
		found = true
	}
	return found
}

func releasedVersion(version string) bool {
	if !strings.HasPrefix(version, "v") {
		return false
	}
	components := strings.Split(version[1:], ".")
	if len(components) != semanticVersionComponents {
		return false
	}
	for _, component := range components {
		if !validVersionComponent(component) {
			return false
		}
	}
	return version != "v0.0.0"
}

func validVersionComponent(component string) bool {
	if component == "" || len(component) > 1 && component[0] == '0' {
		return false
	}
	for _, character := range component {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
