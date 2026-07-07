package main

import (
	"bytes"
	"os"
	"path"
	"strings"
	"testing"
)

func runRSACmd(t *testing.T, args []string, stdin string) (string, string, error) {
	t.Helper()
	cmd := newEncCmd(getDefaultOptions())
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(stdin))
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestRSASignVerifyEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "This is a test of RSA sign/verify.\n"

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	for _, hash := range []string{"sha256", "sha384", "sha512"} {
		sig, _, err := runRSACmd(t,
			[]string{"rsa", "sign", "--hash=" + hash, "--private-key", privateKeyFilename},
			message)
		if err != nil {
			t.Fatalf("%v: sign failed: %v", hash, err)
		}

		sigFilename := path.Join(tempDir, "sig."+hash)
		if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
			t.Fatal(err)
		}

		verified, _, err := runRSACmd(t,
			[]string{"rsa", "verify", "--hash=" + hash, "--public-key", publicKeyFilename, "--signature", sigFilename},
			message)
		if err != nil {
			t.Fatalf("%v: verify failed: %v", hash, err)
		}
		if verified != message {
			t.Fatalf("%v: expected verify output %q, got %q", hash, message, verified)
		}
	}
}

func TestRSASignVerifyKeyFlagAlias(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "alias test"

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"rsa", "sign", "-k", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	verified, _, err := runRSACmd(t,
		[]string{"rsa", "verify", "-k", publicKeyFilename, "--signature", sigFilename},
		message)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified != message {
		t.Fatalf("expected verify output %q, got %q", message, verified)
	}
}

func TestRSAVerifyTamperedSignatureRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "do not trust this"

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"rsa", "sign", "--private-key", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	tampered := []byte(sig)
	tampered[0] ^= 0xff
	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, tampered, 0600); err != nil {
		t.Fatal(err)
	}

	if out, _, err := runRSACmd(t,
		[]string{"rsa", "verify", "--public-key", publicKeyFilename, "--signature", sigFilename},
		message); err == nil {
		t.Fatalf("expected error verifying tampered signature, got nil (stdout=%q)", out)
	}
}

func TestRSAVerifyTamperedMessageRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "original message"

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"rsa", "sign", "--private-key", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	if out, _, err := runRSACmd(t,
		[]string{"rsa", "verify", "--public-key", publicKeyFilename, "--signature", sigFilename},
		"tampered message"); err == nil {
		t.Fatalf("expected error verifying tampered message, got nil (stdout=%q)", out)
	}
}

func TestRSAVerifyWrongKeyRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	otherPublicKeyFilename := path.Join(tempDir, "other-pub.key")
	message := "sign with one key, verify with another"

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--public-key", otherPublicKeyFilename},
		""); err != nil {
		t.Fatalf("other keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"rsa", "sign", "--private-key", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	if out, _, err := runRSACmd(t,
		[]string{"rsa", "verify", "--public-key", otherPublicKeyFilename, "--signature", sigFilename},
		message); err == nil {
		t.Fatalf("expected error verifying with wrong public key, got nil (stdout=%q)", out)
	}
}

func TestRSAVerifyMissingSignatureFlagRejected(t *testing.T) {
	tempDir := t.TempDir()
	publicKeyFilename := path.Join(tempDir, "pub.key")

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "verify", "--public-key", publicKeyFilename},
		"some message"); err == nil {
		t.Fatal("expected error verifying without --signature flag, got nil")
	}
}

func TestRSASignInvalidHashRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, _, err := runRSACmd(t,
		[]string{"rsa", "sign", "--hash=bogus", "--private-key", privateKeyFilename},
		"message"); err == nil {
		t.Fatal("expected error for invalid --hash, got nil")
	}
}
