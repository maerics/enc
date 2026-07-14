package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"
)

func writeJWEKeyFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	filename := path.Join(dir, name)
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filename, key, 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func generateJWERSAKeys(t *testing.T, dir, prefix string) (privateKeyFilename, publicKeyFilename string) {
	t.Helper()
	privateKeyFilename = path.Join(dir, prefix+"priv.key")
	publicKeyFilename = path.Join(dir, prefix+"pub.key")
	if _, _, err := runJWTCmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	return privateKeyFilename, publicKeyFilename
}

func decodeJWEHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 token parts, got %v (%q)", len(parts), token)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse header JSON: %v", err)
	}
	return header
}

func TestJWEDirEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, "Hello, JWE!")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %v (%q)", len(parts), token)
	}
	if parts[1] != "" {
		t.Fatalf("expected empty encrypted-key segment for alg=dir, got %q", parts[1])
	}

	plaintext, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, token)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if plaintext != "Hello, JWE!" {
		t.Fatalf("expected plaintext %q, got %q", "Hello, JWE!", plaintext)
	}
}

func TestJWEDirAllEncVariants(t *testing.T) {
	tempDir := t.TempDir()
	for _, enc := range jweEncNames {
		encAlg := jweEncAlgorithms[enc]
		keyFilename := writeJWEKeyFile(t, tempDir, enc+".key", encAlg.KeySize)

		token, _, err := runJWTCmd(t,
			[]string{"jwe", "--alg=dir", "--enc=" + enc, "--key", keyFilename}, "secret data")
		if err != nil {
			t.Fatalf("%v: encrypt failed: %v", enc, err)
		}

		plaintext, _, err := runJWTCmd(t,
			[]string{"jwe", "-d", "--alg=dir", "--enc=" + enc, "--key", keyFilename}, token)
		if err != nil {
			t.Fatalf("%v: decrypt failed: %v", enc, err)
		}
		if plaintext != "secret data" {
			t.Fatalf("%v: expected plaintext %q, got %q", enc, "secret data", plaintext)
		}
	}
}

func TestJWERSAOAEPEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename, publicKeyFilename := generateJWERSAKeys(t, tempDir, "")

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=RSA-OAEP-256", "--enc=A256GCM", "--public-key", publicKeyFilename},
		"Hello, RSA-OAEP!")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %v", len(parts))
	}
	if parts[1] == "" {
		t.Fatal("expected non-empty encrypted-key segment for alg=RSA-OAEP-256")
	}

	plaintext, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=RSA-OAEP-256", "--enc=A256GCM", "--private-key", privateKeyFilename},
		token)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if plaintext != "Hello, RSA-OAEP!" {
		t.Fatalf("expected plaintext %q, got %q", "Hello, RSA-OAEP!", plaintext)
	}
}

func TestJWEDirWrongKeySizeRejected(t *testing.T) {
	tempDir := t.TempDir()
	wrongSizeKey := writeJWEKeyFile(t, tempDir, "wrong.key", 20)

	if _, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", wrongSizeKey}, "hi"); err == nil {
		t.Fatal("expected error encrypting with wrong-size dir key, got nil")
	} else if !strings.Contains(err.Error(), "invalid key size") {
		t.Fatalf(`expected "invalid key size" error, got %q`, err.Error())
	}

	rightSizeKey := writeJWEKeyFile(t, tempDir, "right.key", 32)
	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", rightSizeKey}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=dir", "--enc=A256GCM", "--key", wrongSizeKey}, token); err == nil {
		t.Fatal("expected error decrypting with wrong-size dir key, got nil")
	} else if !strings.Contains(err.Error(), "invalid key size") {
		t.Fatalf(`expected "invalid key size" error, got %q`, err.Error())
	}
}

func TestJWETamperedCiphertextRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, "Hello, JWE!")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(token), ".")

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xFF
	parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)
	tampered := strings.Join(parts, ".")

	if _, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, tampered); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestJWETamperedTagRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, "Hello, JWE!")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(token), ".")

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	tag[0] ^= 0xFF
	parts[4] = base64.RawURLEncoding.EncodeToString(tag)
	tampered := strings.Join(parts, ".")

	if _, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, tampered); err == nil {
		t.Fatal("expected error decrypting tampered tag, got nil")
	}
}

func TestJWEAlgMismatchRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, publicKeyFilename := generateJWERSAKeys(t, tempDir, "")
	_, _, err = runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=RSA-OAEP-256", "--enc=A256GCM", "--public-key", publicKeyFilename}, token)
	if err == nil {
		t.Fatal("expected error decrypting with mismatched --alg, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf(`expected "does not match" error, got %q`, err.Error())
	}
}

func TestJWEEncMismatchRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 16)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A128GCM", "--key", keyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, _, err = runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, token)
	if err == nil {
		t.Fatal("expected error decrypting with mismatched --enc, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf(`expected "does not match" error, got %q`, err.Error())
	}
}

func TestJWEAutoDetectsAlgAndEncFromHeader(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 16)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A128GCM", "--key", keyFilename}, "hi there")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	plaintext, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--key", keyFilename}, token)
	if err != nil {
		t.Fatalf("decrypt with auto-detected alg/enc failed: %v", err)
	}
	if plaintext != "hi there" {
		t.Fatalf("expected plaintext %q, got %q", "hi there", plaintext)
	}
}

func TestJWEMissingHeaderFieldsRejected(t *testing.T) {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	token := strings.Join([]string{headerB64, "", "", "", ""}, ".")

	if _, _, err := runJWTCmd(t, []string{"jwe", "-d", "--key", "irrelevant"}, token); err == nil {
		t.Fatal("expected error for token missing alg/enc header fields, got nil")
	} else if !strings.Contains(err.Error(), "missing required") {
		t.Fatalf(`expected "missing required" error, got %q`, err.Error())
	}
}

func TestJWEAlgFlagCaseInsensitive(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename, publicKeyFilename := generateJWERSAKeys(t, tempDir, "")

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=rsa-oaep-256", "--enc=a128gcm", "--public-key", publicKeyFilename},
		"hi")
	if err != nil {
		t.Fatalf("encrypt with lowercase flags failed: %v", err)
	}

	header := decodeJWEHeader(t, token)
	if header["alg"] != "RSA-OAEP-256" {
		t.Fatalf("expected canonical alg RSA-OAEP-256 in header, got %#v", header["alg"])
	}
	if header["enc"] != "A128GCM" {
		t.Fatalf("expected canonical enc A128GCM in header, got %#v", header["enc"])
	}

	plaintext, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=Rsa-Oaep-256", "--enc=A128gcm", "--private-key", privateKeyFilename},
		token)
	if err != nil {
		t.Fatalf("decrypt with mixed-case flags failed: %v", err)
	}
	if plaintext != "hi" {
		t.Fatalf("expected plaintext %q, got %q", "hi", plaintext)
	}
}

func TestJWEDefaultAlgAndEncAreDirAndA256GCM(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t, []string{"jwe", "--key", keyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	header := decodeJWEHeader(t, token)
	if header["alg"] != "dir" {
		t.Fatalf("expected default alg dir, got %#v", header["alg"])
	}
	if header["enc"] != "A256GCM" {
		t.Fatalf("expected default enc A256GCM, got %#v", header["enc"])
	}
}

func TestJWEDirKeyDashRejected(t *testing.T) {
	_, _, err := runJWTCmd(t, []string{"jwe", "--alg=dir", "--key", "-"}, "hi")
	if err == nil {
		t.Fatal(`expected an error for "--key=-", got nil`)
	}
	if !strings.Contains(err.Error(), `does not support "-"`) {
		t.Fatalf(`expected a "does not support -" error, got %q`, err.Error())
	}

	_, _, err = runJWTCmd(t, []string{"jwe", "--alg=dir"}, "hi")
	if err == nil {
		t.Fatal("expected an error for the omitted --key flag, got nil")
	}
	if !strings.Contains(err.Error(), "missing required") {
		t.Fatalf(`expected a "missing required" error, got %q`, err.Error())
	}
}

func TestJWEMissingKeyRejected(t *testing.T) {
	if _, _, err := runJWTCmd(t, []string{"jwe", "--alg=RSA-OAEP-256"}, "hi"); err == nil {
		t.Fatal("expected error for omitted --public-key, got nil")
	} else if !strings.Contains(err.Error(), "missing or invalid value") {
		t.Fatalf(`expected "missing or invalid value" error, got %q`, err.Error())
	}
}

func TestJWEWrongRSAKeyRejected(t *testing.T) {
	tempDir := t.TempDir()
	_, publicKeyFilename := generateJWERSAKeys(t, tempDir, "one-")
	otherPrivateKeyFilename, _ := generateJWERSAKeys(t, tempDir, "two-")

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=RSA-OAEP-256", "--public-key", publicKeyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if _, _, err := runJWTCmd(t,
		[]string{"jwe", "-d", "--alg=RSA-OAEP-256", "--private-key", otherPrivateKeyFilename}, token); err == nil {
		t.Fatal("expected error decrypting with the wrong RSA private key, got nil")
	}
}

func TestJWEInvalidAlgRejected(t *testing.T) {
	if _, _, err := runJWTCmd(t, []string{"jwe", "--alg=bogus"}, "hi"); err == nil {
		t.Fatal("expected error for invalid --alg, got nil")
	}
}

func TestJWEInvalidEncRejected(t *testing.T) {
	if _, _, err := runJWTCmd(t, []string{"jwe", "--enc=bogus"}, "hi"); err == nil {
		t.Fatal("expected error for invalid --enc, got nil")
	}
}

func TestJWEDump(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--enc=A256GCM", "--key", keyFilename}, "Hello, JWE!")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	dumpOut, _, err := runJWTCmd(t, []string{"jwe", "dump"}, token)
	if err != nil {
		t.Fatalf("dump failed: %v", err)
	}

	var dumped struct {
		Header       map[string]any `json:"header"`
		EncryptedKey string         `json:"encryptedKey"`
		IV           string         `json:"iv"`
		Ciphertext   string         `json:"ciphertext"`
		Tag          string         `json:"tag"`
	}
	if err := json.Unmarshal([]byte(dumpOut), &dumped); err != nil {
		t.Fatalf("invalid dump JSON %q: %v", dumpOut, err)
	}

	if dumped.Header["alg"] != "dir" || dumped.Header["enc"] != "A256GCM" {
		t.Fatalf("unexpected header: %v", dumped.Header)
	}
	if dumped.EncryptedKey != "" {
		t.Fatalf("expected empty encryptedKey for alg=dir, got %q", dumped.EncryptedKey)
	}
	iv, err := hex.DecodeString(dumped.IV)
	if err != nil || len(iv) != 12 {
		t.Fatalf("expected a 12-byte hex iv, got %q (err=%v)", dumped.IV, err)
	}
	tag, err := hex.DecodeString(dumped.Tag)
	if err != nil || len(tag) != 16 {
		t.Fatalf("expected a 16-byte hex tag, got %q (err=%v)", dumped.Tag, err)
	}
	if _, err := hex.DecodeString(dumped.Ciphertext); err != nil {
		t.Fatalf("ciphertext %q is not valid hex: %v", dumped.Ciphertext, err)
	}
}

func TestJWEDumpRSAHasEncryptedKey(t *testing.T) {
	tempDir := t.TempDir()
	_, publicKeyFilename := generateJWERSAKeys(t, tempDir, "")

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=RSA-OAEP-256", "--public-key", publicKeyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	dumpOut, _, err := runJWTCmd(t, []string{"jwe", "dump"}, token)
	if err != nil {
		t.Fatalf("dump failed: %v", err)
	}
	var dumped struct {
		EncryptedKey string `json:"encryptedKey"`
	}
	if err := json.Unmarshal([]byte(dumpOut), &dumped); err != nil {
		t.Fatalf("invalid dump JSON %q: %v", dumpOut, err)
	}
	encryptedKey, err := hex.DecodeString(dumped.EncryptedKey)
	if err != nil {
		t.Fatalf("encryptedKey %q is not valid hex: %v", dumped.EncryptedKey, err)
	}
	if len(encryptedKey) != 256 {
		t.Fatalf("expected a 256-byte encrypted key (2048-bit RSA-OAEP), got %v bytes", len(encryptedKey))
	}
}

func TestJWEDumpIgnoresDecodeFlag(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := writeJWEKeyFile(t, tempDir, "cek.key", 32)

	token, _, err := runJWTCmd(t,
		[]string{"jwe", "--alg=dir", "--key", keyFilename}, "hi")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	out1, _, err := runJWTCmd(t, []string{"jwe", "dump"}, token)
	if err != nil {
		t.Fatalf("dump failed: %v", err)
	}
	out2, _, err := runJWTCmd(t, []string{"-d", "jwe", "dump"}, token)
	if err != nil {
		t.Fatalf("dump with -d failed: %v", err)
	}
	if out1 != out2 {
		t.Fatalf("dump output differs with -d flag:\n%v\nvs\n%v", out1, out2)
	}
}

func TestJWEDumpMalformedToken(t *testing.T) {
	for _, token := range []string{"not-a-jwe", "one.two.three", "one.two.three.four.five.six"} {
		if _, _, err := runJWTCmd(t, []string{"jwe", "dump"}, token); err == nil {
			t.Fatalf("expected error for malformed token %q, got nil", token)
		}
	}
}

func TestJWEDumpInvalidHeaderJSON(t *testing.T) {
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	token := strings.Join([]string{badHeader, "", "", "", ""}, ".")
	if _, _, err := runJWTCmd(t, []string{"jwe", "dump"}, token); err == nil {
		t.Fatal("expected error for invalid header JSON, got nil")
	}
}
