package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var benchmarkStrings []string
var benchmarkPlan admittedPlan

const benchmarkProfiles = 4
const benchmarkControls = 20

func BenchmarkBoundedEnvironment(b *testing.B) {
	environment := []string{"PATH=value", "HOME=value", "TEMP=value", "SYSTEMROOT=value"}
	for b.Loop() {
		admitted, err := boundedStrings(environment, true)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkStrings = admitted
	}
}

func BenchmarkAdmitPlan(b *testing.B) {
	root := b.TempDir()
	if err := os.Mkdir(filepath.Join(root, "module"), 0o700); err != nil {
		b.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	plan := Plan{ID: "benchmark", Profiles: make([]Profile, benchmarkProfiles)}
	for profileIndex := range plan.Profiles {
		profile := &plan.Profiles[profileIndex]
		profile.ID = fmt.Sprintf("profile_%d", profileIndex)
		profile.Controls = make([]Control, benchmarkControls)
		for controlIndex := range profile.Controls {
			directory := ""
			if controlIndex%2 != 0 {
				directory = "module"
			}
			profile.Controls[controlIndex] = Control{
				ID: fmt.Sprintf("control_%d", controlIndex), Name: "Benchmark Control",
				Command: Command{Executable: executable, Directory: directory, Timeout: time.Second, OutputLimit: 1},
			}
		}
	}
	b.ResetTimer()
	for b.Loop() {
		admitted, admitErr := admit(root, plan)
		if admitErr != nil {
			b.Fatal(admitErr)
		}
		benchmarkPlan = admitted
	}
}
