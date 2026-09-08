package cve

import "testing"

func TestValue(t *testing.T) {
	if Value() != "internal" {
		t.Fatal(Value())
	}
}
