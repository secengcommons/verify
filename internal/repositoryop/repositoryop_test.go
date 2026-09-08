package repositoryop

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/secengcommons/proctree"
)

type fixture struct {
	Value string `json:"value"`
}

func TestEncodeDecode(t *testing.T) {
	encoded, err := Encode("operation", fixture{Value: "value"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded fixture
	if err = Decode(bytes.NewReader(encoded), "operation", &decoded); err != nil || decoded.Value != "value" {
		t.Fatalf("decode = (%#v, %v)", decoded, err)
	}
	var empty Specification[struct{}, struct{}]
	if err = Decode(bytes.NewReader(Empty("empty")), "empty", &empty); err != nil {
		t.Fatalf("empty operation error = %v", err)
	}
	for _, source := range [][]byte{
		nil,
		append(encoded, '\n'),
		bytes.Replace(encoded, []byte(`"operation":"operation"`), []byte(`"operation":"other"`), 1),
		bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":2`), 1),
		bytes.Replace(encoded, []byte(`"type":"`+Type+`"`), []byte(`"type":"other"`), 1),
		bytes.Replace(encoded, []byte(`"value":"value"`), []byte(`"unknown":"value"`), 1),
		[]byte(`{"type":"` + Type + `","version":1,"operation":"operation","specification":{}}`),
		[]byte(`{"type":"` + Type + `","version":1,"operation":"operation","specification":{},"unknown":true}`),
	} {
		if err = Decode(bytes.NewReader(source), "operation", &decoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("source %q error = %v", source, err)
		}
	}
}

func TestBoundsAndOwners(t *testing.T) {
	if _, err := Encode("operation", func() {}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("encode error = %v", err)
	}
	if _, err := Encode("operation", fixture{Value: strings.Repeat("x", MaxBytes)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized encode error = %v", err)
	}
	var decoded fixture
	if err := decodeExact([]byte(`{"value":"one"}{"value":"two"}`), &decoded); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing specification error = %v", err)
	}
	if err := Decode(nil, "operation", &fixture{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil reader error = %v", err)
	}
	if err := Decode(strings.NewReader("{}"), "operation", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil target error = %v", err)
	}
	if err := Decode(strings.NewReader(strings.Repeat("x", MaxBytes+1)), "operation", &fixture{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestTimeoutOwnership(t *testing.T) {
	if InnerTimeout(time.Minute) != time.Minute || OuterTimeout(time.Minute) != time.Minute+proctree.MaxCleanupTimeout {
		t.Fatal("ordinary timeout ownership differs")
	}
	maximumInner := proctree.MaxTimeout - proctree.MaxCleanupTimeout
	if InnerTimeout(proctree.MaxTimeout) != maximumInner || OuterTimeout(proctree.MaxTimeout) != proctree.MaxTimeout {
		t.Fatal("maximum timeout ownership differs")
	}
	for _, invalid := range []time.Duration{0, -1, proctree.MaxTimeout + 1} {
		if InnerTimeout(invalid) != invalid || OuterTimeout(invalid) != invalid {
			t.Fatalf("invalid timeout %s was normalised", invalid)
		}
	}
}

func FuzzDecode(f *testing.F) {
	valid, err := Encode("operation", fixture{Value: "value"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > MaxBytes {
			return
		}
		var first, second fixture
		firstErr := Decode(bytes.NewReader(source), "operation", &first)
		secondErr := Decode(bytes.NewReader(source), "operation", &second)
		if first != second || (firstErr == nil) != (secondErr == nil) || errors.Is(firstErr, ErrInvalid) != errors.Is(secondErr, ErrInvalid) {
			t.Fatal("repository operation decoding differs")
		}
		if firstErr == nil {
			encoded, encodeErr := Encode("operation", first)
			if encodeErr != nil || !bytes.Equal(encoded, source) {
				t.Fatalf("successful operation is not canonical: %v", encodeErr)
			}
		}
	})
}
