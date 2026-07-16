package main

import (
	"bytes"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
)

func TestOTPRoundTrip(t *testing.T) {
	for _, message := range [][]byte{
		[]byte(""),
		[]byte("secret!"),
		[]byte("Hello, OTP! 🔐"),
		mustRand(1024),
	} {
		padFilename := path.Join(t.TempDir(), "otp.pad")

		encryptCmd := newEncCmd(getDefaultOptions())
		encryptCmd.SetArgs([]string{"otp", "--pad", padFilename})
		encryptCmd.SetIn(bytes.NewReader(message))
		ciphertext := new(bytes.Buffer)
		encryptCmd.SetOut(ciphertext)
		if err := encryptCmd.Execute(); err != nil {
			t.Fatalf("unexpected encryption error: %v", err)
		}

		pad, err := os.ReadFile(padFilename)
		if err != nil {
			t.Fatalf("failed to read generated pad file: %v", err)
		}
		if len(pad) != len(message) {
			t.Fatalf("pad length %v != message length %v", len(pad), len(message))
		}

		decryptCmd := newEncCmd(getDefaultOptions())
		decryptCmd.SetArgs([]string{"otp", "--decrypt", "--pad", padFilename})
		decryptCmd.SetIn(bytes.NewReader(ciphertext.Bytes()))
		plaintext := new(bytes.Buffer)
		decryptCmd.SetOut(plaintext)
		if err := decryptCmd.Execute(); err != nil {
			t.Fatalf("unexpected decryption error: %v", err)
		}

		if !bytes.Equal(plaintext.Bytes(), message) {
			t.Fatalf("roundtrip failed: wanted %q, got %q", message, plaintext.Bytes())
		}
	}
}

func TestOTPMissingPadFlag(t *testing.T) {
	for _, args := range [][]string{
		{"otp"},
		{"otp", "--decrypt"},
	} {
		cmd := newEncCmd(getDefaultOptions())
		cmd.SetArgs(args)
		cmd.SetIn(bytes.NewReader([]byte("secret!")))
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("args=%#v: expected an error for missing --pad, got nil", args)
		}
		if !strings.Contains(err.Error(), `missing required "--pad" flag`) {
			t.Fatalf("args=%#v: unexpected error: %v", args, err)
		}
	}
}

func TestOTPPadDashRejected(t *testing.T) {
	for _, args := range [][]string{
		{"otp", "--pad", "-"},
		{"otp", "--decrypt", "--pad", "-"},
	} {
		cmd := newEncCmd(getDefaultOptions())
		cmd.SetArgs(args)
		cmd.SetIn(bytes.NewReader([]byte("secret!")))
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("args=%#v: expected an error for \"--pad=-\", got nil", args)
		}
		if !strings.Contains(err.Error(), `does not support "-"`) {
			t.Fatalf("args=%#v: expected a \"does not support -\" error, got %q", args, err.Error())
		}
	}
}

func TestOTPRefusesToOverwritePad(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")

	firstCmd := newEncCmd(getDefaultOptions())
	firstCmd.SetArgs([]string{"otp", "--pad", padFilename})
	firstCmd.SetIn(bytes.NewReader([]byte("message one")))
	firstCmd.SetOut(new(bytes.Buffer))
	if err := firstCmd.Execute(); err != nil {
		t.Fatalf("unexpected error on first encrypt: %v", err)
	}
	firstPad, err := os.ReadFile(padFilename)
	if err != nil {
		t.Fatal(err)
	}

	secondCmd := newEncCmd(getDefaultOptions())
	secondCmd.SetArgs([]string{"otp", "--pad", padFilename})
	secondCmd.SetIn(bytes.NewReader([]byte("message two")))
	secondCmd.SetOut(new(bytes.Buffer))
	secondCmd.SetErr(new(bytes.Buffer))
	if err := secondCmd.Execute(); err == nil {
		t.Fatal("expected an error when encrypting to an existing pad file without --force, got nil")
	}
	unchangedPad, err := os.ReadFile(padFilename)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstPad, unchangedPad) {
		t.Fatal("pad file was modified despite the overwrite being rejected")
	}

	forcedCmd := newEncCmd(getDefaultOptions())
	forcedCmd.SetArgs([]string{"otp", "--pad", padFilename, "--force"})
	forcedCmd.SetIn(bytes.NewReader([]byte("message two")))
	forcedCmd.SetOut(new(bytes.Buffer))
	if err := forcedCmd.Execute(); err != nil {
		t.Fatalf("unexpected error when encrypting with --force: %v", err)
	}
}

func TestOTPDecryptPadLengthMismatch(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")
	mustWrite(t, padFilename, mustRand(4))

	cmd := newEncCmd(getDefaultOptions())
	cmd.SetArgs([]string{"otp", "--decrypt", "--pad", padFilename})
	cmd.SetIn(bytes.NewReader(mustRand(8)))
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for mismatched pad/ciphertext length, got nil")
	}
	if !strings.Contains(err.Error(), "does not match ciphertext length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOTPDeletePad(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")
	message := []byte("delete me after decrypt")

	encryptCmd := newEncCmd(getDefaultOptions())
	encryptCmd.SetArgs([]string{"otp", "--pad", padFilename})
	encryptCmd.SetIn(bytes.NewReader(message))
	ciphertext := new(bytes.Buffer)
	encryptCmd.SetOut(ciphertext)
	if err := encryptCmd.Execute(); err != nil {
		t.Fatalf("unexpected encryption error: %v", err)
	}

	decryptCmd := newEncCmd(getDefaultOptions())
	decryptCmd.SetArgs([]string{"otp", "--decrypt", "--pad", padFilename, "--delete-pad"})
	decryptCmd.SetIn(bytes.NewReader(ciphertext.Bytes()))
	decryptCmd.SetOut(new(bytes.Buffer))
	if err := decryptCmd.Execute(); err != nil {
		t.Fatalf("unexpected decryption error: %v", err)
	}

	if _, err := os.Stat(padFilename); !os.IsNotExist(err) {
		t.Fatalf("expected pad file to be deleted after successful decrypt, stat err=%v", err)
	}
}

func TestOTPDeletePadKeptOnFailure(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")
	mustWrite(t, padFilename, mustRand(4))

	cmd := newEncCmd(getDefaultOptions())
	cmd.SetArgs([]string{"otp", "--decrypt", "--pad", padFilename, "--delete-pad"})
	cmd.SetIn(bytes.NewReader(mustRand(8))) // mismatched length -> decrypt fails
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a decryption error, got nil")
	}

	if _, err := os.Stat(padFilename); err != nil {
		t.Fatalf("expected pad file to survive a failed decrypt, stat err=%v", err)
	}
}
