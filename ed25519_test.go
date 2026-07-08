package main

import (
	"os"
	"path"
	"testing"
)

func TestEd25519SignVerifyEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "This is a test of Ed25519 sign/verify.\n"

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t,
		[]string{"ed25519", "sign", "--private-key", privateKeyFilename},
		message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	verified, _, err := runRSACmd(t,
		[]string{"ed25519", "verify", "--public-key", publicKeyFilename, "--signature", sigFilename},
		message)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified != message {
		t.Fatalf("expected verify output %q, got %q", message, verified)
	}
}

func TestEd25519SignVerifyKeyFlagAlias(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "alias test"

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"ed25519", "sign", "-k", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	verified, _, err := runRSACmd(t,
		[]string{"ed25519", "verify", "-k", publicKeyFilename, "--signature", sigFilename},
		message)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified != message {
		t.Fatalf("expected verify output %q, got %q", message, verified)
	}
}

func TestEd25519VerifyTamperedSignatureRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "do not trust this"

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"ed25519", "sign", "--private-key", privateKeyFilename}, message)
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
		[]string{"ed25519", "verify", "--public-key", publicKeyFilename, "--signature", sigFilename},
		message); err == nil {
		t.Fatalf("expected error verifying tampered signature, got nil (stdout=%q)", out)
	}
}

func TestEd25519VerifyTamperedMessageRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	message := "original message"

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"ed25519", "sign", "--private-key", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	if out, _, err := runRSACmd(t,
		[]string{"ed25519", "verify", "--public-key", publicKeyFilename, "--signature", sigFilename},
		"tampered message"); err == nil {
		t.Fatalf("expected error verifying tampered message, got nil (stdout=%q)", out)
	}
}

func TestEd25519VerifyWrongKeyRejected(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	otherPublicKeyFilename := path.Join(tempDir, "other-pub.key")
	message := "sign with one key, verify with another"

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--public-key", otherPublicKeyFilename},
		""); err != nil {
		t.Fatalf("other keygen failed: %v", err)
	}

	sig, _, err := runRSACmd(t, []string{"ed25519", "sign", "--private-key", privateKeyFilename}, message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sigFilename := path.Join(tempDir, "sig.bin")
	if err := os.WriteFile(sigFilename, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	if out, _, err := runRSACmd(t,
		[]string{"ed25519", "verify", "--public-key", otherPublicKeyFilename, "--signature", sigFilename},
		message); err == nil {
		t.Fatalf("expected error verifying with wrong public key, got nil (stdout=%q)", out)
	}
}

func TestEd25519VerifyMissingSignatureFlagRejected(t *testing.T) {
	tempDir := t.TempDir()
	publicKeyFilename := path.Join(tempDir, "pub.key")

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "verify", "--public-key", publicKeyFilename},
		"some message"); err == nil {
		t.Fatal("expected error verifying without --signature flag, got nil")
	}
}

func TestEd25519ExtractPublicKeyEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")
	extractedPublicKeyFilename := path.Join(tempDir, "extracted-pub.key")

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, _, err := runRSACmd(t,
		[]string{"ed25519", "extract", "--private-key", privateKeyFilename, "--public-key", extractedPublicKeyFilename},
		""); err != nil {
		t.Fatalf("extract failed: %v", err)
	}

	generated, err := os.ReadFile(publicKeyFilename)
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := os.ReadFile(extractedPublicKeyFilename)
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(extracted) {
		t.Fatalf("expected extracted public key to match generated public key\ngenerated=%q\nextracted=%q",
			generated, extracted)
	}
}
