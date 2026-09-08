package goverify

import (
	"bufio"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestCheckCoverage(t *testing.T) {
	t.Parallel()
	profile := "mode: atomic\nexample.test/module/value.go:1.1,2.2 2 1\nexample.test/module/value.go:3.1,3.2 1 2\nexample.test/module/value.go:4.1,4.1 0 1\n"
	coverage, err := CheckCoverage(strings.NewReader(profile))
	want := Coverage{Rows: 3, Statements: 3, Covered: 3}
	if err != nil || !reflect.DeepEqual(coverage, want) || CoverageText(coverage) != "3 statements covered across 3 rows" {
		t.Fatalf("CheckCoverage = (%#v, %v)", coverage, err)
	}
}

func TestCheckCoverageAcceptsLongAdmittedLine(t *testing.T) {
	t.Parallel()
	profile := "mode: atomic\n" + strings.Repeat("a", 5_000) + ".go:1.1,1.2 1 1\n"
	coverage, err := CheckCoverage(strings.NewReader(profile))
	if err != nil || coverage.Rows != 1 || coverage.Covered != 1 {
		t.Fatalf("coverage = (%#v, %v)", coverage, err)
	}
}

func TestCheckCoverageAcceptsPrintablePathSpaces(t *testing.T) {
	profile := "mode: atomic\nexample.test/module/value file.go:1.1,1.2 1 1\n"
	coverage, err := CheckCoverage(strings.NewReader(profile))
	if err != nil || coverage != (Coverage{Rows: 1, Statements: 1, Covered: 1}) {
		t.Fatalf("coverage = (%#v, %v)", coverage, err)
	}
}

func TestCoverageTextUsesSingularCounts(t *testing.T) {
	t.Parallel()
	if got := CoverageText(Coverage{Statements: 1, Rows: 1}); got != "1 statement covered across 1 row" {
		t.Fatalf("CoverageText = %q", got)
	}
}

func TestCheckCoverageRejectsIncomplete(t *testing.T) {
	t.Parallel()
	profile := "mode: atomic\nexample.test/module/value.go:1.1,2.2 2000 1\nexample.test/module/value.go:3.1,3.2 1 0\n"
	coverage, err := CheckCoverage(strings.NewReader(profile))
	if !errors.Is(err, ErrIncompleteCoverage) || coverage.Statements != 2001 || coverage.Covered != 2000 ||
		err.Error() != "go statement coverage is incomplete: 1 uncovered of 2001 statements; first example.test/module/value.go:3.1,3.2" {
		t.Fatalf("CheckCoverage = (%#v, %v)", coverage, err)
	}
}

func TestCheckCoverageRejectsInvalidProfiles(t *testing.T) {
	t.Parallel()
	validRow := "example.test/module/value.go:1.1,2.2 1 1"
	tests := []string{
		"",
		"mode: set\n" + validRow + "\n",
		"mode: atomic",
		"mode: atomic\n",
		"mode: atomic\n\n",
		"mode: atomic\ninvalid\n",
		"mode: atomic\nexample.test/module/value.go:1.1,2.2 0 1\n",
		"mode: atomic\nexample.test/module/value.go:01.1,2.2 1 1\n",
		"mode: atomic\nexample.test/module/value.go:1.1,2.2 1 00\n",
		"mode: atomic\nexample.test/module/value.go:1.1,2.2 1 invalid\n",
		"mode: atomic\nexample.test/module/value.go:1.1,2.2 18446744073709551616 1\n",
		"mode: atomic\nexample.test/module/value.go:1.1,2.2 1 18446744073709551616\n",
		"mode: atomic\n" + strings.Repeat("x", MaxCoverageLineBytes) + "\n",
	}
	for _, profile := range tests {
		if _, err := CheckCoverage(strings.NewReader(profile)); !errors.Is(err, ErrCoverageProfile) {
			t.Fatalf("profile %q error = %v", profile, err)
		}
	}
	if _, err := CheckCoverage(nil); !errors.Is(err, ErrCoverageProfile) {
		t.Fatalf("nil profile error = %v", err)
	}
}

func TestCoverageReaderBoundsAndFailures(t *testing.T) {
	t.Parallel()
	owner := coverageReader{reader: bufio.NewReader(strings.NewReader("\n")), bytes: MaxCoverageBytes}
	if _, err := owner.line(); !errors.Is(err, ErrCoverageProfile) {
		t.Fatalf("byte bound error = %v", err)
	}
	readErr := errors.New("read")
	owner = coverageReader{reader: bufio.NewReader(errorReader{err: readErr})}
	if _, err := owner.line(); !errors.Is(err, readErr) {
		t.Fatalf("read error = %v", err)
	}
	owner = coverageReader{result: Coverage{Rows: MaxCoverageRows}}
	if err := owner.add([]byte("module/file.go:1.1,1.2 1 1")); !errors.Is(err, ErrCoverageProfile) {
		t.Fatalf("row bound error = %v", err)
	}
	owner = coverageReader{result: Coverage{Statements: math.MaxUint64}}
	if err := owner.add([]byte("module/file.go:1.1,1.2 1 1")); !errors.Is(err, ErrCoverageProfile) {
		t.Fatalf("statement overflow error = %v", err)
	}
}

func TestCoverageParsingHelpers(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{[]byte("row"), []byte("row 1 "), []byte("row  1")} {
		if _, _, _, ok := coverageFields(value); ok {
			t.Fatalf("coverage fields accepted %q", value)
		}
	}
	invalidIdentities := [][]byte{
		[]byte("value.go"),
		[]byte("value.go:"),
		[]byte("value.go:0.1,1.1"),
		[]byte("value.go:1.,1.1"),
		[]byte("value.go:1.0,1.1"),
		[]byte("value.go:1.1,0.1"),
		[]byte("value.go:1.1,1."),
		[]byte("value.go:1.1,1.0"),
		append([]byte("value"), 0xff, ':', '1', '.', '1', ',', '1', '.', '1'),
		[]byte("value\u0085.go:1.1,1.1"),
	}
	for _, value := range invalidIdentities {
		if validCoverageIdentity(value) {
			t.Fatalf("coverage identity accepted %q", value)
		}
	}
	if parsed, remainder, ok := decimalPrefix([]byte("1."), '.'); ok || parsed != 0 || remainder != nil {
		t.Fatalf("decimal prefix = (%d, %q, %t)", parsed, remainder, ok)
	}
}

func FuzzCheckCoverage(f *testing.F) {
	f.Add([]byte("mode: atomic\nmodule/file.go:1.1,1.2 1 1\n"))
	f.Add([]byte("mode: atomic\nmodule/file.go:1.1,1.2 1 0\n"))
	f.Fuzz(func(t *testing.T, profile []byte) {
		if len(profile) > MaxCoverageLineBytes+1 {
			return
		}
		first, firstErr := CheckCoverage(strings.NewReader(string(profile)))
		second, secondErr := CheckCoverage(strings.NewReader(string(profile)))
		if !reflect.DeepEqual(first, second) || !sameCoverageError(firstErr, secondErr) {
			t.Fatalf("coverage differs: (%#v, %v) and (%#v, %v)", first, firstErr, second, secondErr)
		}
		if firstErr == nil && (first.Rows <= 0 || first.Statements == 0 || first.Covered != first.Statements) {
			t.Fatalf("invalid complete coverage = %#v", first)
		}
	})
}

func sameCoverageError(left, right error) bool {
	return (left == nil) == (right == nil) && errors.Is(left, ErrCoverageProfile) == errors.Is(right, ErrCoverageProfile) &&
		errors.Is(left, ErrIncompleteCoverage) == errors.Is(right, ErrIncompleteCoverage)
}
