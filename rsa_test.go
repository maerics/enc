package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"path"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestRsaGenerate(t *testing.T) {
	privatePattern := fmt.Sprintf(
		"-----BEGIN %v-----\n([^-]+)\n-----END %v-----\n",
		RsaPrivateKeyPEMType, RsaPrivateKeyPEMType)
	publicPattern := fmt.Sprintf(
		"-----BEGIN %v-----\n([^-]+)\n-----END %v-----\n",
		RsaPublicKeyPEMType, RsaPublicKeyPEMType)

	outputRegex := regexp.MustCompile(privatePattern + publicPattern)

	for i, eg := range []struct {
		args    []string
		keySize int
	}{
		{args: []string{"rsa", "generate"}},
		{args: []string{"rsa", "generate", "-s1024"}, keySize: 1024},
		{args: []string{"rsa", "generate", "-s", "1024"}, keySize: 1024},
		{args: []string{"rsa", "generate", "--key-size=1024"}, keySize: 1024},
		{args: []string{"rsa", "generate", "--key-size=2048"}, keySize: 2048},
		{args: []string{"rsa", "generate", "--key-size=4096"}, keySize: 4096},
	} {
		generateCmd := newEncCmd(getDefaultOptions())
		generateCmd.SetArgs(eg.args)
		generateCmd.SetIn(bytes.NewReader([]byte{}))
		stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
		generateCmd.SetOut(stdout)
		generateCmd.SetErr(stderr)
		if err := generateCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		actualStdout := stdout.Bytes()
		actualStderr := stderr.Bytes()

		if len(actualStderr) != 0 {
			t.Fatalf("example %v: unexpected stderr %v", i, string(actualStderr))
		}

		m := outputRegex.FindAllStringSubmatch(string(actualStdout), -1)
		if m == nil {
			t.Fatalf("example %v: output does not match \n%v\n%v", i, outputRegex, string(actualStdout))
		} else {
			// log.Printf("OK:\npriv=%v\npub=%v", m[0][1], m[0][2])
			nonBase64 := regexp.MustCompile(`[^A-Za-z0-9+/=]`)
			privDataLen := len(mustDecodeBase64(nonBase64.ReplaceAllString(m[0][1], "")))
			pubDataLen := len(mustDecodeBase64(nonBase64.ReplaceAllString(m[0][2], "")))
			ratio := float64(privDataLen) / float64(pubDataLen)
			if pubDataLen > privDataLen || (math.Abs(4.3-ratio) > 0.2) {
				t.Errorf("unexpected key sizes (ratio=%v): keySize=%v, private.size=%v, public.size=%v\npriv=%v,\npub=%v",
					ratio, eg.keySize, 8*privDataLen, 8*pubDataLen, m[0][1], m[0][2])
			}
		}
	}
}

func TestRsaEncryptionEndToEnd(t *testing.T) {
	plaintext := "This is a test of RSA e2e encryption.\n"
	tempDir := t.TempDir()
	privateKeyFilename := func(x int) string { return path.Join(tempDir, fmt.Sprintf("priv.key%v", x)) }
	publicKeyFilename := func(x int) string { return path.Join(tempDir, fmt.Sprintf("pub.key%v", x)) }

	for i, eg := range []struct {
		generateArgs []string
		encryptArgs  []string
		decryptArgs  []string
	}{
		{ // Canonical, explicit arguments.
			[]string{"rsa", "generate", "--public-key", publicKeyFilename(0), "--private-key", privateKeyFilename(0)},
			[]string{"rsa", "--public-key", publicKeyFilename(0)},
			[]string{"rsa", "--decrypt", "--private-key", privateKeyFilename(0)},
		},
		{ // Shorthand arguments.
			[]string{"rsa", "gen", "-s1024", "--public-key", publicKeyFilename(1), "--private-key", privateKeyFilename(1)},
			[]string{"rsa", "--public-key", publicKeyFilename(1)},
			[]string{"rsa", "-d", "--private-key", privateKeyFilename(1)},
		},
	} {
		// Generate keypair
		generateCmd := newEncCmd(getDefaultOptions())
		generateCmd.SetArgs(eg.generateArgs)
		if err := generateCmd.Execute(); err != nil {
			t.Fatalf("example %v while generating: %v", i, err)
		}

		// Encrypt
		encryptCmd := newEncCmd(getDefaultOptions())
		encryptCmd.SetArgs(eg.encryptArgs)
		encryptCmd.SetIn(strings.NewReader(plaintext))
		encryptStdout := &bytes.Buffer{}
		encryptCmd.SetOut(encryptStdout)
		if err := encryptCmd.Execute(); err != nil {
			t.Fatalf("example %v while encrypting: %v", i, err)
		}
		ciphertext := encryptStdout.Bytes()

		// Decrypt
		decryptCmd := newEncCmd(getDefaultOptions())
		decryptCmd.SetArgs(eg.decryptArgs)
		decryptCmd.SetIn(bytes.NewReader(ciphertext))
		decryptStdout := &bytes.Buffer{}
		decryptCmd.SetOut(decryptStdout)
		if err := decryptCmd.Execute(); err != nil {
			t.Fatalf("example %v while decrypting: %v", i, err)
		}

		decrypted := decryptStdout.String()
		if decrypted != plaintext {
			t.Fatalf("example %v expected %q, got %q", i, decrypted, plaintext)
		}
	}
}

func TestRsaExtract(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := func(x int) string { return path.Join(tempDir, fmt.Sprintf("priv.key%v", x)) }

	for i, eg := range []struct {
		generateArgs []string
	}{
		{generateArgs: []string{"rsa", "generate", "--private-key", privateKeyFilename(0)}},
		{generateArgs: []string{"rsa", "generate", "-s256", "--private-key", privateKeyFilename(1)}},
		{generateArgs: []string{"rsa", "generate", "--key-size=1024", "--private-key", privateKeyFilename(2)}},
	} {
		// Run the "rsa generate" command, store the private key to a file, and the public key in memory.
		generateCmd := newEncCmd(getDefaultOptions())
		generateCmd.SetArgs(eg.generateArgs)
		generateCmd.SetIn(bytes.NewReader([]byte{}))
		stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
		generateCmd.SetOut(stdout)
		generateCmd.SetErr(stderr)
		if err := generateCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		generatedPublicKeyBytes := stdout.Bytes()
		_ = stderr.Bytes()

		// Run the "rsa extract" cmd to ensure the same public key is generated.
		extractCmd := newEncCmd(getDefaultOptions())
		extractCmd.SetArgs([]string{"rsa", "extract", "--private-key", eg.generateArgs[len(eg.generateArgs)-1]})
		stdout, stderr = new(bytes.Buffer), new(bytes.Buffer)
		extractCmd.SetOut(stdout)
		extractCmd.SetErr(stderr)
		if err := extractCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		extractedPublicKeyBytes := stdout.Bytes()
		if !reflect.DeepEqual(extractedPublicKeyBytes, generatedPublicKeyBytes) {
			t.Fatalf("generated/extracted public keys do not match for example %v:\ngenerated: %v\nextracted: %v",
				i, generatedPublicKeyBytes, extractedPublicKeyBytes)
		}
	}
}

func mustDecodeBase64(s string) []byte {
	if bs, err := base64.StdEncoding.DecodeString(s); err != nil {
		log.Fatalf("FATAL: %v -- %v", err, s)
		return nil
	} else {
		return bs
	}
}
