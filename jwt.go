package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

const (
	FlagNameAlg           = "alg"
	FlagNameKid           = "kid"
	FlagNameClaim         = "claim"
	FlagNameExpiresIn     = "expires-in"
	FlagNameOmitIat       = "omit-iat"
	FlagNameAppendNewline = "append-newline"
)

type jwtAlgFamily string

const (
	jwtAlgFamilyNone  jwtAlgFamily = "none"
	jwtAlgFamilyHMAC  jwtAlgFamily = "hmac"
	jwtAlgFamilyRSA   jwtAlgFamily = "rsa"
	jwtAlgFamilyEdDSA jwtAlgFamily = "eddsa"
)

type jwtAlg struct {
	Name   string
	Hash   crypto.Hash
	Family jwtAlgFamily
}

var jwtAlgorithms = map[string]jwtAlg{
	"none":  {"none", 0, jwtAlgFamilyNone},
	"HS256": {"HS256", crypto.SHA256, jwtAlgFamilyHMAC},
	"HS384": {"HS384", crypto.SHA384, jwtAlgFamilyHMAC},
	"HS512": {"HS512", crypto.SHA512, jwtAlgFamilyHMAC},
	"RS256": {"RS256", crypto.SHA256, jwtAlgFamilyRSA},
	"RS384": {"RS384", crypto.SHA384, jwtAlgFamilyRSA},
	"RS512": {"RS512", crypto.SHA512, jwtAlgFamilyRSA},
	"EdDSA": {"EdDSA", 0, jwtAlgFamilyEdDSA},
}

var jwtAlgNames = []string{"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "EdDSA"}

func addJWTCommand(rootCmd *cobra.Command, o *Options) {
	var algName string
	var kid string
	var claims []string
	var expiresIn time.Duration
	var omitIat bool

	short := "Sign input claims as a JWT"
	if o.Decode {
		short = "Verify a JWT and decode its claims"
	}

	cmd := &cobra.Command{
		Use:   "jwt",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.Decode {
				return jwtVerifyCmd(cmd, o, algName)
			}
			signAlgName := algName
			if signAlgName == "" {
				signAlgName = "HS256"
			}
			alg, ok := jwtAlgorithms[signAlgName]
			if !ok {
				return fmt.Errorf("invalid %q flag %q: must be one of %v",
					"--"+FlagNameAlg, signAlgName, strings.Join(jwtAlgNames, ", "))
			}
			return jwtSignCmd(cmd, o, alg, kid, claims, expiresIn, omitIat)
		},
	}

	cmd.Flags().StringVarP(&algName, FlagNameAlg, "a", "",
		"signing algorithm: "+strings.Join(jwtAlgNames, ", ")+
			` (default "HS256" when signing; when verifying, taken from the token's "alg" header, default "HS256")`)
	cmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "",
		"HMAC secret key filename (for HS* algorithms)")
	cmd.Flags().StringVar(&o.PrivateKeyFilename, FlagNamePrivateKey, "",
		"private key filename, for signing (RSA PKCS1 PEM for RS* algorithms, Ed25519 PKCS8 PEM for EdDSA)")
	cmd.Flags().StringVar(&o.PublicKeyFilename, FlagNamePublicKey, "",
		"public key filename, for verifying (RSA PKCS1 PEM for RS* algorithms, Ed25519 PKIX PEM for EdDSA)")
	cmd.Flags().StringVar(&kid, FlagNameKid, "",
		"key ID to embed in the header; ignored when verifying")
	cmd.Flags().StringArrayVar(&claims, FlagNameClaim, nil,
		`set a claim as key=value, repeatable; value is parsed as JSON when possible `+
			`(e.g. --claim admin=true), otherwise used as a raw string; ignored when verifying`)
	cmd.Flags().DurationVar(&expiresIn, FlagNameExpiresIn, 0,
		`set the "exp" claim to now plus this duration (e.g. 1h30m); ignored when verifying`)
	cmd.Flags().BoolVar(&omitIat, FlagNameOmitIat, false,
		`omit the automatic "iat" (issued at) claim; ignored when verifying`)
	cmd.Flags().BoolVarP(&o.AppendNewline, FlagNameAppendNewline, "n", o.AppendNewline,
		"append a trailing newline to the output")

	rootCmd.AddCommand(cmd)
}

func jwtSignCmd(cmd *cobra.Command, o *Options, alg jwtAlg, kid string, claimFlags []string, expiresIn time.Duration, omitIat bool) error {
	warnIrrelevantJWTKeyFlags(alg, o)

	hmacKey, rsaKey, edKey, err := jwtResolveSigningKey(cmd, o, alg)
	if err != nil {
		return err
	}

	input, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read claims from input: %v", err)
	}
	claimsMap := map[string]any{}
	if input = bytes.TrimSpace(input); len(input) > 0 {
		if err := json.Unmarshal(input, &claimsMap); err != nil {
			return fmt.Errorf("failed to parse claims JSON from input: %v", err)
		}
	}

	if !omitIat {
		if _, exists := claimsMap["iat"]; !exists {
			claimsMap["iat"] = time.Now().Unix()
		}
	}
	if expiresIn > 0 {
		claimsMap["exp"] = time.Now().Add(expiresIn).Unix()
	}
	for _, kv := range claimFlags {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("invalid %v %q: must be key=value", "--"+FlagNameClaim, kv)
		}
		var parsed any
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			parsed = v
		}
		claimsMap[k] = parsed
	}

	claimsJSON, err := json.Marshal(claimsMap)
	if err != nil {
		return fmt.Errorf("failed to encode claims: %v", err)
	}

	header := map[string]any{"alg": alg.Name, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to encode header: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig, err := jwtSign(alg, hmacKey, rsaKey, edKey, []byte(signingInput))
	if err != nil {
		return fmt.Errorf("failed to sign token: %v", err)
	}

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	out := cmd.OutOrStdout()
	if _, err := io.WriteString(out, token); err != nil {
		return fmt.Errorf("failed to write token: %v", err)
	}
	if o.AppendNewline {
		if _, err := io.WriteString(out, "\n"); err != nil {
			return fmt.Errorf("failed to append trailing newline: %v", err)
		}
	}
	return nil
}

func jwtVerifyCmd(cmd *cobra.Command, o *Options, algName string) error {
	input, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read token from input: %v", err)
	}
	token := strings.TrimSpace(string(input))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT: expected 3 dot-separated parts, got %v", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse header JSON: %v", err)
	}

	var alg jwtAlg
	if algName != "" {
		var ok bool
		alg, ok = jwtAlgorithms[algName]
		if !ok {
			return fmt.Errorf("invalid %q flag %q: must be one of %v",
				"--"+FlagNameAlg, algName, strings.Join(jwtAlgNames, ", "))
		}
		if header.Alg != alg.Name {
			return fmt.Errorf("token alg %q does not match expected %v=%q", header.Alg, "--"+FlagNameAlg, alg.Name)
		}
	} else {
		autoAlgName := header.Alg
		if autoAlgName == "" {
			autoAlgName = "HS256"
		}
		var ok bool
		alg, ok = jwtAlgorithms[autoAlgName]
		if !ok {
			return fmt.Errorf(`token has unsupported "alg" header %q: must be one of %v`,
				autoAlgName, strings.Join(jwtAlgNames, ", "))
		}
	}

	warnIrrelevantJWTKeyFlags(alg, o)

	hmacKey, rsaKey, edKey, err := jwtResolveVerifyingKey(cmd, o, alg)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := jwtVerify(alg, hmacKey, rsaKey, edKey, signingInput, sig); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode claims: %v", err)
	}
	out := cmd.OutOrStdout()
	if _, err := out.Write(claimsJSON); err != nil {
		return fmt.Errorf("failed to write claims: %v", err)
	}
	if o.AppendNewline {
		if _, err := io.WriteString(out, "\n"); err != nil {
			return fmt.Errorf("failed to append trailing newline: %v", err)
		}
	}
	return nil
}

func warnIrrelevantJWTKeyFlags(alg jwtAlg, o *Options) {
	switch alg.Family {
	case jwtAlgFamilyNone:
		if o.KeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for alg=none", "--"+FlagNameKey)
		}
		if o.PrivateKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for alg=none", "--"+FlagNamePrivateKey)
		}
		if o.PublicKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for alg=none", "--"+FlagNamePublicKey)
		}
	case jwtAlgFamilyHMAC:
		if o.PrivateKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for HMAC algorithms", "--"+FlagNamePrivateKey)
		}
		if o.PublicKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for HMAC algorithms", "--"+FlagNamePublicKey)
		}
	case jwtAlgFamilyRSA, jwtAlgFamilyEdDSA:
		if o.KeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for %v algorithms", "--"+FlagNameKey, alg.Family)
		}
	}
}

// jwtResolveSigningKey/jwtResolveVerifyingKey and jwtSign/jwtVerify below take one
// concrete key parameter per supported asymmetric family (rsaKey, edKey) rather than a
// crypto.Signer/crypto.PublicKey abstraction, matching this codebase's existing
// concrete-key-type style. A future ECDSA addition (see TODO.md) will need this same
// widening again for a 4th key type.

func jwtResolveSigningKey(cmd *cobra.Command, o *Options, alg jwtAlg) ([]byte, *rsa.PrivateKey, ed25519.PrivateKey, error) {
	switch alg.Family {
	case jwtAlgFamilyHMAC:
		key, err := jwtReadHMACKey(o)
		return key, nil, nil, err
	case jwtAlgFamilyRSA:
		privateKey, err := readRSAPrivateKey(cmd, o)
		return nil, privateKey, nil, err
	case jwtAlgFamilyEdDSA:
		privateKey, err := readEd25519PrivateKey(cmd, o)
		return nil, nil, privateKey, err
	default:
		return nil, nil, nil, nil
	}
}

func jwtResolveVerifyingKey(cmd *cobra.Command, o *Options, alg jwtAlg) ([]byte, *rsa.PublicKey, ed25519.PublicKey, error) {
	switch alg.Family {
	case jwtAlgFamilyHMAC:
		key, err := jwtReadHMACKey(o)
		return key, nil, nil, err
	case jwtAlgFamilyRSA:
		publicKey, err := readRSAPublicKey(cmd, o)
		return nil, publicKey, nil, err
	case jwtAlgFamilyEdDSA:
		publicKey, err := readEd25519PublicKey(cmd, o)
		return nil, nil, publicKey, err
	default:
		return nil, nil, nil, nil
	}
}

func jwtSign(alg jwtAlg, hmacKey []byte, rsaKey *rsa.PrivateKey, edKey ed25519.PrivateKey, signingInput []byte) ([]byte, error) {
	switch alg.Family {
	case jwtAlgFamilyNone:
		return nil, nil
	case jwtAlgFamilyHMAC:
		h := hmac.New(alg.Hash.New, hmacKey)
		h.Write(signingInput)
		return h.Sum(nil), nil
	case jwtAlgFamilyRSA:
		h := alg.Hash.New()
		h.Write(signingInput)
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, alg.Hash, h.Sum(nil))
	case jwtAlgFamilyEdDSA:
		return ed25519.Sign(edKey, signingInput), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg.Name)
	}
}

func jwtVerify(alg jwtAlg, hmacKey []byte, rsaKey *rsa.PublicKey, edKey ed25519.PublicKey, signingInput, sig []byte) error {
	switch alg.Family {
	case jwtAlgFamilyNone:
		if len(sig) != 0 {
			return fmt.Errorf("alg=none requires an empty signature")
		}
		return nil
	case jwtAlgFamilyHMAC:
		h := hmac.New(alg.Hash.New, hmacKey)
		h.Write(signingInput)
		if !hmac.Equal(h.Sum(nil), sig) {
			return fmt.Errorf("invalid signature")
		}
		return nil
	case jwtAlgFamilyRSA:
		h := alg.Hash.New()
		h.Write(signingInput)
		return rsa.VerifyPKCS1v15(rsaKey, alg.Hash, h.Sum(nil), sig)
	case jwtAlgFamilyEdDSA:
		if !ed25519.Verify(edKey, signingInput, sig) {
			return fmt.Errorf("invalid signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm %q", alg.Name)
	}
}

func jwtReadHMACKey(o *Options) ([]byte, error) {
	if o.KeyFilename == "" {
		return nil, fmt.Errorf(`missing required %q flag`, "--"+FlagNameKey)
	}
	if isStd(o.KeyFilename) {
		return nil, fmt.Errorf(`the %q flag does not support "-" (stdin); provide a file path`, "--"+FlagNameKey)
	}
	key, err := os.ReadFile(o.KeyFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key bytes: %v", err)
	}
	return key, nil
}
