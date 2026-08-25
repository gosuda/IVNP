package ssu2

import (
	"testing"
)

func TestPathValidatorRequiresMatchingUnexpiredResponse(t *testing.T) {
	var validator PathValidator
	if !validator.Begin([]byte("challenge"), 10) {
		t.Fatal("Begin failed")
	}
	if validator.Validate([]byte("wrong"), 1) {
		t.Fatal("wrong response accepted")
	}
	if !validator.Validate([]byte("challenge"), 10) {
		t.Fatal("matching response rejected")
	}
	if validator.Validate([]byte("challenge"), 10) {
		t.Fatal("response reused")
	}
	validator.Begin([]byte("challenge"), 10)
	if !validator.Expired(11) {
		t.Fatal("deadline not expired")
	}
}
