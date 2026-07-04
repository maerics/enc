package main

import (
	"encoding/base64"
	"testing"
)

func TestParsePad(t *testing.T) {
	if pad, err := parsePad("=", false); err != nil || pad != '=' {
		t.Errorf("parsePad(%q, false) = (%q, %v), want ('=', nil)", "=", pad, err)
	}
	if pad, err := parsePad("*", false); err != nil || pad != '*' {
		t.Errorf("parsePad(%q, false) = (%q, %v), want ('*', nil)", "*", pad, err)
	}
	if pad, err := parsePad("=", true); err != nil || pad != base64.NoPadding {
		t.Errorf("parsePad(%q, true) = (%v, %v), want (NoPadding, nil)", "=", pad, err)
	}
	if _, err := parsePad("**", false); err == nil {
		t.Error(`parsePad("**", false) expected error, got nil`)
	}
	if _, err := parsePad("", false); err == nil {
		t.Error(`parsePad("", false) expected error, got nil`)
	}
}
