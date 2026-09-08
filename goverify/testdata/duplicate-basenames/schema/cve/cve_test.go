package cve

import "testing"

func TestValue(t *testing.T) {
	if Value() != "schema" {
		t.Fatal(Value())
	}
}
