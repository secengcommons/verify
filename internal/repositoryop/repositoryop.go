package repositoryop

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/secengcommons/proctree"
)

const Type = "secverify-repository-operation"
const Version = 1
const MaxBytes = 1 << 20
const decimalBase = 10

var ErrInvalid = errors.New("invalid repository operation")

type Specification[O, M any] struct {
	Owner    O `json:"owner"`
	Material M `json:"material"`
}

type envelope struct {
	Type          string          `json:"type"`
	Version       int             `json:"version"`
	Operation     string          `json:"operation"`
	Specification json.RawMessage `json:"specification"`
}

func Empty(operation string) []byte {
	var result []byte
	result = append(result, `{"type":`...)
	result = strconv.AppendQuote(result, Type)
	result = append(result, `,"version":`...)
	result = strconv.AppendInt(result, Version, decimalBase)
	result = append(result, `,"operation":`...)
	result = strconv.AppendQuote(result, operation)
	return append(result, `,"specification":{"owner":{},"material":{}}}`...)
}

func InnerTimeout(requested time.Duration) time.Duration {
	if requested <= 0 || requested > proctree.MaxTimeout {
		return requested
	}
	return min(requested, proctree.MaxTimeout-proctree.MaxCleanupTimeout)
}

func OuterTimeout(requested time.Duration) time.Duration {
	if requested <= 0 || requested > proctree.MaxTimeout {
		return requested
	}
	return InnerTimeout(requested) + proctree.MaxCleanupTimeout
}

func Encode(operation string, specification any) ([]byte, error) {
	material, err := json.Marshal(specification)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	encoded, err := json.Marshal(envelope{Type: Type, Version: Version, Operation: operation, Specification: material})
	if err != nil || len(encoded) > MaxBytes {
		return nil, errors.Join(ErrInvalid, err)
	}
	return encoded, nil
}

func Decode(reader io.Reader, operation string, specification any) error {
	if reader == nil || specification == nil {
		return ErrInvalid
	}
	source, err := read(reader)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var value envelope
	if err = decoder.Decode(&value); err != nil || value.Type != Type || value.Version != Version || value.Operation != operation {
		return errors.Join(ErrInvalid, err)
	}
	if err = decodeCanonical(value.Specification, specification); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, source) {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}

func decodeCanonical(source []byte, target any) error {
	if err := decodeExact(source, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, source) {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}

func decodeExact(source []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}

func read(reader io.Reader) ([]byte, error) {
	buffer := make([]byte, MaxBytes+1)
	read, err := io.ReadFull(reader, buffer)
	if read == 0 || read > MaxBytes || err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errors.Join(ErrInvalid, err)
	}
	return buffer[:read], nil
}
