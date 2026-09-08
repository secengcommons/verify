package goverify

import (
	"os"
	"testing"

	verify "github.com/secengcommons/verify"
)

func TestMain(testingMain *testing.M) {
	if handled, code := verify.DispatchProcessOwner(os.Args); handled {
		os.Exit(code)
	}
	os.Exit(testingMain.Run())
}

func testExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}
