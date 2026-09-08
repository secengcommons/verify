package safeoutput

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/secengcommons/verify/internal/exactwrite"
)

const escapeBufferBytes = 4 << 10
const hexadecimalShift = 4
const hexadecimalMask = 1<<hexadecimalShift - 1
const hexadecimalDigits = "0123456789abcdef"
const asciiDelete = 0x7f
const escapedByteBytes = 4

type characterKind uint8

const (
	characterPrintable characterKind = iota
	characterLineFeed
	characterUnsafe
)

func Write(output io.Writer, value []byte) error {
	if len(value) == 0 {
		return nil
	}
	if safe(value) {
		if err := exactwrite.Bytes(output, value); err != nil {
			return err
		}
		if value[len(value)-1] != '\n' {
			return exactwrite.Bytes(output, []byte("\n"))
		}
		return nil
	}
	return writeEscaped(output, value)
}

func Diagnostic(value string) string {
	var result strings.Builder
	result.Grow(diagnosticBytes(value))
	lineWhitespace := true
	for index := 0; index < len(value); {
		if workflowCommandText(value[index:], lineWhitespace) {
			escaped := escapedByte(value[index])
			result.Write(escaped[:])
			index++
			lineWhitespace = false
			continue
		}
		kind, size := classify([]byte(value[index:]))
		if kind == characterPrintable && value[index] != '\t' {
			result.WriteString(value[index : index+size])
		} else {
			for _, encoded := range []byte(value[index : index+size]) {
				escaped := escapedByte(encoded)
				result.Write(escaped[:])
			}
		}
		lineWhitespace = nextLineWhitespace(lineWhitespace, kind, []byte(value[index:index+size]))
		index += size
	}
	return result.String()
}

func diagnosticBytes(value string) int {
	total := 0
	lineWhitespace := true
	for index := 0; index < len(value); {
		if workflowCommandText(value[index:], lineWhitespace) {
			total += escapedByteBytes
			index++
			lineWhitespace = false
			continue
		}
		kind, size := classify([]byte(value[index:]))
		if kind == characterPrintable && value[index] != '\t' {
			total += size
		} else {
			total += size * escapedByteBytes
		}
		lineWhitespace = nextLineWhitespace(lineWhitespace, kind, []byte(value[index:index+size]))
		index += size
	}
	return total
}

func safe(value []byte) bool {
	lineWhitespace := true
	for index := 0; index < len(value); {
		if workflowCommand(value[index:], lineWhitespace) {
			return false
		}
		kind, size := classify(value[index:])
		if kind == characterUnsafe {
			return false
		}
		lineWhitespace = nextLineWhitespace(lineWhitespace, kind, value[index:index+size])
		index += size
	}
	return true
}

func workflowCommand(value []byte, lineWhitespace bool) bool {
	return lineWhitespace && bytes.HasPrefix(value, []byte("::")) ||
		bytes.HasPrefix(value, []byte("##vso[")) || bytes.HasPrefix(value, []byte("##["))
}

func workflowCommandText(value string, lineWhitespace bool) bool {
	return lineWhitespace && strings.HasPrefix(value, "::") ||
		strings.HasPrefix(value, "##vso[") || strings.HasPrefix(value, "##[")
}

func nextLineWhitespace(current bool, kind characterKind, value []byte) bool {
	if kind == characterLineFeed {
		return true
	}
	if !current || kind == characterUnsafe {
		return false
	}
	character, _ := utf8.DecodeRune(value)
	return unicode.IsSpace(character)
}

func classify(value []byte) (characterKind, int) {
	character := value[0]
	switch {
	case character == '\n':
		return characterLineFeed, 1
	case character == '\t' || character >= ' ' && character < utf8.RuneSelf && character != asciiDelete:
		return characterPrintable, 1
	case character < utf8.RuneSelf:
		return characterUnsafe, 1
	default:
		decoded, size := utf8.DecodeRune(value)
		if decoded == utf8.RuneError && size == 1 || !strconv.IsPrint(decoded) {
			return characterUnsafe, size
		}
		return characterPrintable, size
	}
}

type renderer struct {
	output io.Writer
	buffer [escapeBufferBytes]byte
	used   int
}

func writeEscaped(output io.Writer, value []byte) error {
	owner := renderer{output: output}
	lineWhitespace := true
	lastLineFeed := false
	for index := 0; index < len(value); {
		if workflowCommand(value[index:], lineWhitespace) {
			if err := owner.appendEscapedByte(value[index]); err != nil {
				return err
			}
			index++
			lineWhitespace = false
			lastLineFeed = false
			continue
		}
		kind, size := classify(value[index:])
		if err := owner.append(value[index:index+size], kind); err != nil {
			return err
		}
		lineWhitespace = nextLineWhitespace(lineWhitespace, kind, value[index:index+size])
		lastLineFeed = kind == characterLineFeed
		index += size
	}
	if !lastLineFeed {
		if err := owner.appendByte('\n'); err != nil {
			return err
		}
	}
	return owner.flush()
}

func (owner *renderer) append(value []byte, kind characterKind) error {
	if kind != characterUnsafe {
		return owner.appendBytes(value)
	}
	for _, encoded := range value {
		if err := owner.appendEscapedByte(encoded); err != nil {
			return err
		}
	}
	return nil
}

func (owner *renderer) appendEscapedByte(value byte) error {
	escaped := escapedByte(value)
	return owner.appendBytes(escaped[:])
}

func escapedByte(value byte) [escapedByteBytes]byte {
	return [escapedByteBytes]byte{'\\', 'x', hexadecimalDigits[value>>hexadecimalShift], hexadecimalDigits[value&hexadecimalMask]}
}

func (owner *renderer) appendBytes(value []byte) error {
	for _, character := range value {
		if err := owner.appendByte(character); err != nil {
			return err
		}
	}
	return nil
}

func (owner *renderer) appendByte(value byte) error {
	if owner.used == len(owner.buffer) {
		if err := owner.flush(); err != nil {
			return err
		}
	}
	owner.buffer[owner.used] = value
	owner.used++
	return nil
}

func (owner *renderer) flush() error {
	if owner.used == 0 {
		return nil
	}
	if err := exactwrite.Bytes(owner.output, owner.buffer[:owner.used]); err != nil {
		return err
	}
	owner.used = 0
	return nil
}
