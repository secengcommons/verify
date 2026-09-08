package goverify

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

const MaxCoverageBytes = 64 << 20
const MaxCoverageLineBytes = 64 << 10
const minimumCoverageRowBytes = 14
const MaxCoverageRows = MaxCoverageBytes / minimumCoverageRowBytes

const decimalRadix = 10
const asciiZero = '0'
const asciiNine = '9'
const asciiSpace = ' '

var ErrCoverageProfile = errors.New("invalid Go coverage profile")
var ErrIncompleteCoverage = errors.New("go statement coverage is incomplete")

// Coverage summarises one complete atomic Go coverage profile
type Coverage struct {
	Rows       int    // Rows is the parsed source-range count
	Statements uint64 // Statements is the declared statement count
	Covered    uint64 // Covered is the statement count with non-zero execution
}

// CheckCoverage requires a bounded complete atomic coverage profile
func CheckCoverage(reader io.Reader) (Coverage, error) {
	if reader == nil {
		return Coverage{}, ErrCoverageProfile
	}
	owner := coverageReader{reader: bufio.NewReader(reader)}
	mode, err := owner.line()
	if err != nil || string(mode) != "mode: atomic" {
		return Coverage{}, errors.Join(ErrCoverageProfile, err)
	}
	for {
		line, lineErr := owner.line()
		if errors.Is(lineErr, io.EOF) {
			break
		}
		if lineErr != nil {
			return Coverage{}, errors.Join(ErrCoverageProfile, lineErr)
		}
		if err = owner.add(line); err != nil {
			return Coverage{}, err
		}
	}
	if owner.result.Rows == 0 || owner.result.Statements == 0 {
		return Coverage{}, ErrCoverageProfile
	}
	if owner.result.Covered != owner.result.Statements {
		return owner.result, fmt.Errorf("%w: %d uncovered of %d statements; first %s", ErrIncompleteCoverage,
			owner.result.Statements-owner.result.Covered, owner.result.Statements, owner.firstUncovered)
	}
	return owner.result, nil
}

type coverageReader struct {
	reader         *bufio.Reader
	bytes          int
	result         Coverage
	firstUncovered string
}

func (owner *coverageReader) line() ([]byte, error) {
	var line []byte
	for {
		fragment, err := owner.reader.ReadSlice('\n')
		owner.bytes += len(fragment)
		if owner.bytes > MaxCoverageBytes || len(line) > MaxCoverageLineBytes-len(fragment) {
			return nil, ErrCoverageProfile
		}
		if line == nil && !errors.Is(err, bufio.ErrBufferFull) {
			line = fragment
		} else {
			line = append(line, fragment...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) != 0 {
				return nil, ErrCoverageProfile
			}
			return nil, io.EOF
		}
		if err != nil || len(line) == 0 || line[len(line)-1] != '\n' {
			return nil, errors.Join(ErrCoverageProfile, err)
		}
		return line[:len(line)-1], nil
	}
}

func (owner *coverageReader) add(line []byte) error {
	identity, statementText, countText, ok := coverageFields(line)
	if !ok || !validCoverageIdentity(identity) || owner.result.Rows == MaxCoverageRows {
		return ErrCoverageProfile
	}
	statements, ok := unsignedDecimal(statementText)
	if !ok || statements > math.MaxUint64-owner.result.Statements {
		return ErrCoverageProfile
	}
	count, ok := unsignedDecimal(countText)
	if !ok {
		return ErrCoverageProfile
	}
	owner.result.Rows++
	owner.result.Statements += statements
	if count != 0 {
		owner.result.Covered += statements
	} else if statements != 0 && owner.firstUncovered == "" {
		owner.firstUncovered = string(identity)
	}
	return nil
}

func coverageFields(line []byte) (identity, statements, count []byte, ok bool) {
	countSeparator := bytes.LastIndexByte(line, asciiSpace)
	if countSeparator <= 0 || countSeparator == len(line)-1 {
		return nil, nil, nil, false
	}
	statementSeparator := bytes.LastIndexByte(line[:countSeparator], asciiSpace)
	if statementSeparator <= 0 || statementSeparator == countSeparator-1 {
		return nil, nil, nil, false
	}
	return line[:statementSeparator], line[statementSeparator+1 : countSeparator], line[countSeparator+1:], true
}

func validCoverageIdentity(value []byte) bool {
	separator := bytes.LastIndexByte(value, ':')
	if separator <= 0 || separator == len(value)-1 || !validCoveragePath(value[:separator]) {
		return false
	}
	position := value[separator+1:]
	startLine, remainder, ok := decimalPrefix(position, '.')
	if !ok || startLine == 0 {
		return false
	}
	startColumn, remainder, ok := decimalPrefix(remainder, ',')
	if !ok || startColumn == 0 {
		return false
	}
	endLine, remainder, ok := decimalPrefix(remainder, '.')
	if !ok || endLine == 0 {
		return false
	}
	endColumn, ok := positiveDecimal(remainder)
	return ok && endColumn != 0
}

func validCoveragePath(value []byte) bool {
	if len(value) == 0 || !utf8.Valid(value) {
		return false
	}
	for len(value) != 0 {
		character, size := utf8.DecodeRune(value)
		if !strconv.IsPrint(character) {
			return false
		}
		value = value[size:]
	}
	return true
}

func decimalPrefix(value []byte, separator byte) (uint64, []byte, bool) {
	index := bytes.IndexByte(value, separator)
	if index <= 0 || index == len(value)-1 {
		return 0, nil, false
	}
	parsed, ok := positiveDecimal(value[:index])
	return parsed, value[index+1:], ok
}

func positiveDecimal(value []byte) (uint64, bool) {
	parsed, ok := unsignedDecimal(value)
	return parsed, ok && parsed != 0
}

func unsignedDecimal(value []byte) (uint64, bool) {
	if len(value) == 0 || len(value) > 1 && value[0] == asciiZero {
		return 0, false
	}
	var result uint64
	for _, character := range value {
		if character < asciiZero || character > asciiNine {
			return 0, false
		}
		digit := uint64(character - asciiZero)
		if result > (math.MaxUint64-digit)/decimalRadix {
			return 0, false
		}
		result = result*decimalRadix + digit
	}
	return result, true
}

// CoverageText renders a concise complete-coverage result
func CoverageText(value Coverage) string {
	statement, row := "statements", "rows"
	if value.Statements == 1 {
		statement = "statement"
	}
	if value.Rows == 1 {
		row = "row"
	}
	return fmt.Sprintf("%d %s covered across %d %s", value.Statements, statement, value.Rows, row)
}
