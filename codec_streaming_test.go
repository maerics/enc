package main

import (
	"bytes"
	"encoding/base64"
	"path"
	"strings"
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

// Note: these test at the xorNewEncoderO/xorNewDecoderO layer rather than
// through the full CLI (cmd.Execute()). The streaming codec commands funnel
// transcoding errors through transcodeStreaming's log.Fatalf, which calls
// os.Exit and would kill the test binary, not just fail the one test.

func TestXORStrictFlagRejectsShortKey(t *testing.T) {
	keyFilename := path.Join(t.TempDir(), "short.key")
	mustWrite(t, keyFilename, []byte("key")) // 3 bytes, shorter than the message

	w := xorNewEncoderO(new(bytes.Buffer), &Options{Key: keyFilename, Strict: true})
	_, err := w.Write([]byte("a message longer than the key"))
	if err == nil {
		t.Fatal("expected an error when the key is shorter than the input in --strict mode, got nil")
	}
	if !strings.Contains(err.Error(), "key exhausted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestXORStrictFlagAllowsShortKeyByDefault(t *testing.T) {
	keyFilename := path.Join(t.TempDir(), "short.key")
	mustWrite(t, keyFilename, []byte("key")) // 3 bytes, shorter than the message

	w := xorNewEncoderO(new(bytes.Buffer), &Options{Key: keyFilename})
	if _, err := w.Write([]byte("a message longer than the key")); err != nil {
		t.Fatalf("unexpected error without --strict: %v", err)
	}
}
