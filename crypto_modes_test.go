package main

import "testing"

func TestCryptoModeString(t *testing.T) {
	for _, s := range AllCryptoModeStrings {
		m := cryptoMode(s)
		if got := m.String(); got != s {
			t.Errorf("cryptoMode(%q).String() = %q, want %q", s, got, s)
		}
	}
}

func TestCryptoModeType(t *testing.T) {
	var m cryptoMode
	if got, want := m.Type(), "mode"; got != want {
		t.Errorf("cryptoMode.Type() = %q, want %q", got, want)
	}
}

func TestCryptoModeSet(t *testing.T) {
	for _, s := range AllCryptoModeStrings {
		var m cryptoMode
		if err := m.Set(s); err != nil {
			t.Errorf("cryptoMode.Set(%q) returned unexpected error: %v", s, err)
		}
		if string(m) != s {
			t.Errorf("cryptoMode.Set(%q) set value to %q, want %q", s, string(m), s)
		}
	}

	var m cryptoMode = "gcm"
	if err := m.Set("bogus"); err == nil {
		t.Error("cryptoMode.Set(\"bogus\") expected error, got nil")
	} else if want := "must be one of " + cryptoModesString; err.Error() != want {
		t.Errorf("cryptoMode.Set(\"bogus\") error = %q, want %q", err.Error(), want)
	}
	if m != "gcm" {
		t.Errorf("cryptoMode.Set with invalid value should not modify receiver, got %q", m)
	}
}
