package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"
)

func runJWTCmd(t *testing.T, args []string, stdin string) (string, string, error) {
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

func TestJWTHMACEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := path.Join(tempDir, "hmac.key")
	if err := os.WriteFile(keyFilename, []byte("super-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		token, _, err := runJWTCmd(t,
			[]string{"jwt", "--alg=" + alg, "--key", keyFilename, "--claim", "sub=alice"},
			`{"role":"admin"}`)
		if err != nil {
			t.Fatalf("%v: sign failed: %v", alg, err)
		}
		parts := strings.Split(strings.TrimSpace(token), ".")
		if len(parts) != 3 {
			t.Fatalf("%v: expected 3 parts, got %q", alg, token)
		}

		claimsOut, _, err := runJWTCmd(t,
			[]string{"jwt", "-d", "--alg=" + alg, "--key", keyFilename},
			token)
		if err != nil {
			t.Fatalf("%v: verify failed: %v", alg, err)
		}
		var claims map[string]any
		if err := json.Unmarshal([]byte(claimsOut), &claims); err != nil {
			t.Fatalf("%v: invalid claims JSON %q: %v", alg, claimsOut, err)
		}
		if claims["sub"] != "alice" || claims["role"] != "admin" {
			t.Fatalf("%v: unexpected claims: %v", alg, claims)
		}
		if _, ok := claims["iat"]; !ok {
			t.Fatalf("%v: expected automatic iat claim, got %v", alg, claims)
		}
	}
}

func TestJWTRSAEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFilename := path.Join(tempDir, "priv.key")
	publicKeyFilename := path.Join(tempDir, "pub.key")

	if _, _, err := runJWTCmd(t,
		[]string{"rsa", "generate", "--private-key", privateKeyFilename, "--public-key", publicKeyFilename},
		""); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	token, _, err := runJWTCmd(t,
		[]string{"jwt", "--alg=RS256", "--private-key", privateKeyFilename, "--expires-in=1h"},
		`{"sub":"bob"}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	claimsOut, _, err := runJWTCmd(t,
		[]string{"jwt", "-d", "--alg=RS256", "--public-key", publicKeyFilename},
		token)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsOut), &claims); err != nil {
		t.Fatalf("invalid claims JSON %q: %v", claimsOut, err)
	}
	if claims["sub"] != "bob" {
		t.Fatalf("unexpected claims: %v", claims)
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatalf("expected exp claim, got %v", claims)
	}
}

func TestJWTNoneAlg(t *testing.T) {
	token, _, err := runJWTCmd(t, []string{"jwt", "--alg=none", "--omit-iat"}, `{"sub":"eve"}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if !strings.HasSuffix(strings.TrimSpace(token), ".") {
		t.Fatalf("expected empty trailing signature segment, got %q", token)
	}

	claimsOut, _, err := runJWTCmd(t, []string{"jwt", "-d", "--alg=none"}, token)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsOut), &claims); err != nil {
		t.Fatalf("invalid claims JSON %q: %v", claimsOut, err)
	}
	if claims["sub"] != "eve" {
		t.Fatalf("unexpected claims: %v", claims)
	}
}

// Regression test: "--key=-" for an HMAC alg must be rejected with a
// message distinct from the "flag omitted" case.
func TestJWTHMACKeyDashRejected(t *testing.T) {
	_, _, err := runJWTCmd(t, []string{"jwt", "--alg=HS256", "--key", "-"}, `{}`)
	if err == nil {
		t.Fatal(`expected an error for "--key=-", got nil`)
	}
	if !strings.Contains(err.Error(), `does not support "-"`) {
		t.Fatalf(`expected a "does not support -" error, got %q`, err.Error())
	}

	_, _, err = runJWTCmd(t, []string{"jwt", "--alg=HS256"}, `{}`)
	if err == nil {
		t.Fatal("expected an error for the omitted --key flag, got nil")
	}
	if !strings.Contains(err.Error(), "missing required") {
		t.Fatalf(`expected a "missing required" error, got %q`, err.Error())
	}
}

func TestJWTAlgMismatchRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := path.Join(tempDir, "hmac.key")
	if err := os.WriteFile(keyFilename, []byte("super-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	token, _, err := runJWTCmd(t, []string{"jwt", "--alg=HS256", "--key", keyFilename}, `{}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if _, _, err := runJWTCmd(t, []string{"jwt", "-d", "--alg=HS512", "--key", keyFilename}, token); err == nil {
		t.Fatal("expected error verifying with mismatched --alg, got nil")
	}

	if _, _, err := runJWTCmd(t, []string{"jwt", "-d", "--alg=none"}, token); err == nil {
		t.Fatal("expected error verifying HS256 token with --alg=none, got nil")
	}
}

func TestJWTBadSignatureRejected(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := path.Join(tempDir, "hmac.key")
	otherKeyFilename := path.Join(tempDir, "other.key")
	if err := os.WriteFile(keyFilename, []byte("super-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherKeyFilename, []byte("wrong-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	token, _, err := runJWTCmd(t, []string{"jwt", "--alg=HS256", "--key", keyFilename}, `{}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if _, _, err := runJWTCmd(t, []string{"jwt", "-d", "--alg=HS256", "--key", otherKeyFilename}, token); err == nil {
		t.Fatal("expected error verifying with wrong key, got nil")
	}
}

func TestJWTDefaultAlgIsHS256(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := path.Join(tempDir, "hmac.key")
	if err := os.WriteFile(keyFilename, []byte("super-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	// No --alg flag: should default to HS256.
	token, _, err := runJWTCmd(t, []string{"jwt", "--key", keyFilename}, `{}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}
	if header.Alg != "HS256" {
		t.Fatalf("expected default alg HS256, got %q", header.Alg)
	}

	if _, _, err := runJWTCmd(t, []string{"jwt", "-d", "--key", keyFilename}, token); err != nil {
		t.Fatalf("verify with default alg failed: %v", err)
	}
}

func TestJWTVerifyAutoDetectsAlgFromHeader(t *testing.T) {
	tempDir := t.TempDir()
	keyFilename := path.Join(tempDir, "hmac.key")
	if err := os.WriteFile(keyFilename, []byte("super-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	token, _, err := runJWTCmd(t,
		[]string{"jwt", "--alg=HS512", "--key", keyFilename}, `{"sub":"alice"}`)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// No --alg flag on verify: should auto-detect HS512 from the header
	// rather than defaulting to HS256.
	claimsOut, _, err := runJWTCmd(t, []string{"jwt", "-d", "--key", keyFilename}, token)
	if err != nil {
		t.Fatalf("verify with auto-detected alg failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsOut), &claims); err != nil {
		t.Fatalf("invalid claims JSON %q: %v", claimsOut, err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("unexpected claims: %v", claims)
	}
}

func TestJWTInvalidAlgRejected(t *testing.T) {
	if _, _, err := runJWTCmd(t, []string{"jwt", "--alg=bogus"}, `{}`); err == nil {
		t.Fatal("expected error for invalid --alg, got nil")
	}
}

func TestJWTClaimFlagTypes(t *testing.T) {
	token, _, err := runJWTCmd(t, []string{
		"jwt", "--alg=none", "--omit-iat",
		"--claim", "admin=true",
		"--claim", "count=3",
		"--claim", "name=bob",
	}, "")
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	claimsOut, _, err := runJWTCmd(t, []string{"jwt", "-d", "--alg=none"}, token)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsOut), &claims); err != nil {
		t.Fatalf("invalid claims JSON %q: %v", claimsOut, err)
	}
	if claims["admin"] != true {
		t.Fatalf("expected admin=true (bool), got %#v", claims["admin"])
	}
	if claims["count"] != float64(3) {
		t.Fatalf("expected count=3 (number), got %#v", claims["count"])
	}
	if claims["name"] != "bob" {
		t.Fatalf("expected name=\"bob\" (string), got %#v", claims["name"])
	}
}
