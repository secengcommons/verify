package main

import (
	"encoding/base64"
	"runtime/debug"
	"strings"
	"testing"
)

func TestIdentityFromBuild(t *testing.T) {
	t.Parallel()
	clean := gitBuildInfo(strings.Repeat("a", gitCommitHexLength), "false")
	identity := identityFromBuild("0.1.0", clean, true)
	if identity.source != "commit:"+strings.Repeat("a", gitCommitHexLength) || identity.version != "0.1.0" {
		t.Fatalf("clean identity = %#v", identity)
	}
	dirty := gitBuildInfo(strings.Repeat("b", gitCommitHexLength), "true")
	if identity = identityFromBuild(developmentVersion, dirty, true); identity.source != "dirty:"+strings.Repeat("b", gitCommitHexLength) {
		t.Fatalf("dirty identity = %#v", identity)
	}
	sha256 := strings.Repeat("c", gitSHA256HexLength)
	if identity = identityFromBuild(developmentVersion, gitBuildInfo(sha256, "false"), true); identity.source != "commit:"+sha256 {
		t.Fatalf("SHA-256 identity = %#v", identity)
	}
	module := releasedBuildInfo()
	module.Main.Version = "v1.0.0-alpha1"
	module.Main.Sum = moduleSum(1)
	if identity = identityFromBuild("1.0.0-alpha1", module, true); identity.source != "module:v1.0.0-alpha1@"+module.Main.Sum {
		t.Fatalf("module identity = %#v", identity)
	}
	for _, mutate := range []func(*debug.BuildInfo){
		func(value *debug.BuildInfo) { value.Main.Path = "example.test/verify" },
		func(value *debug.BuildInfo) { value.Main.Version = "v1.0.0-alpha2" },
		func(value *debug.BuildInfo) { value.Main.Sum = "invalid" },
		func(value *debug.BuildInfo) { value.Main.Replace = &debug.Module{Path: verifyModule} },
		func(value *debug.BuildInfo) { value.Settings = []debug.BuildSetting{{Key: "vcs", Value: "git"}} },
	} {
		candidate := *module
		mutate(&candidate)
		if identity = identityFromBuild("1.0.0-alpha1", &candidate, true); identity.source != unavailableSource {
			t.Fatalf("invalid module identity = %#v", identity)
		}
	}
	for _, information := range []*debug.BuildInfo{
		nil,
		{},
		{Settings: []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: strings.Repeat("a", gitCommitHexLength)}}},
		gitBuildInfo("invalid", "false"),
		gitBuildInfo(strings.Repeat("z", gitCommitHexLength), "false"),
		{Settings: []debug.BuildSetting{{Key: "vcs", Value: "hg"}, {Key: "vcs.revision", Value: strings.Repeat("a", gitCommitHexLength)}, {Key: "vcs.modified", Value: "false"}}},
		{Settings: append(gitBuildInfo(strings.Repeat("a", gitCommitHexLength), "false").Settings, debug.BuildSetting{Key: "vcs.revision", Value: strings.Repeat("b", gitCommitHexLength)})},
		{Settings: append(gitBuildInfo(strings.Repeat("a", gitCommitHexLength), "false").Settings, debug.BuildSetting{Key: "vcs", Value: "git"})},
		{Settings: append(gitBuildInfo(strings.Repeat("a", gitCommitHexLength), "false").Settings, debug.BuildSetting{Key: "vcs.modified", Value: "false"})},
		gitBuildInfo(strings.Repeat("a", gitCommitHexLength), "unknown"),
	} {
		if got := identityFromBuild(developmentVersion, information, information != nil); got.source != unavailableSource {
			t.Fatalf("unavailable identity = %#v", got)
		}
	}
}

func moduleSum(value byte) string {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = value
	}
	return "h1:" + base64.StdEncoding.EncodeToString(digest)
}

func gitBuildInfo(revision, modified string) *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: revision},
		{Key: "vcs.modified", Value: modified},
	}}
}
