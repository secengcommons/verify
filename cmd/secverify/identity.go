package main

import (
	"crypto/sha256"
	"encoding/base64"
	"runtime"
	"runtime/debug"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const unavailableSource = "unavailable"
const gitCommitHexLength = 40
const gitSHA256HexLength = 64
const maxIdentityTextBytes = 128
const encodedSHA256Bytes = (sha256.Size + 2) / 3 * 4
const moduleSumTextBytes = len("h1:") + encodedSHA256Bytes
const maxModuleVersionBytes = maxIdentityTextBytes - len("module:") - len("@") - moduleSumTextBytes

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
		if identity.source == unavailableSource && !hasVCSMetadata(information.Settings) {
			identity.source = moduleSourceIdentity(information.Main, version)
		}
	}
	return identity
}

func hasVCSMetadata(settings []debug.BuildSetting) bool {
	for _, setting := range settings {
		if setting.Key == "vcs" || setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
			return true
		}
	}
	return false
}

func moduleSourceIdentity(main debug.Module, version string) string {
	if version == developmentVersion || main.Path != verifyModule || main.Version != "v"+version || main.Replace != nil || !validModuleSum(main.Sum) {
		return unavailableSource
	}
	return "module:" + main.Version + "@" + main.Sum
}

func validModuleSum(value string) bool {
	encoded, found := strings.CutPrefix(value, "h1:")
	if !found {
		return false
	}
	digest, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(digest) == sha256.Size && base64.StdEncoding.EncodeToString(digest) == encoded
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
	return len(version) <= maxModuleVersionBytes && version != "v0.0.0" && semver.IsValid(version) && semver.Canonical(version) == version &&
		!module.IsPseudoVersion(version)
}
