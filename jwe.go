package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const FlagNameEnc = "enc"

type jweKeyAlgFamily string

const (
	jweKeyAlgFamilyDir jweKeyAlgFamily = "dir"
	jweKeyAlgFamilyRSA jweKeyAlgFamily = "rsa"
)

type jweKeyAlg struct {
	Name   string
	Family jweKeyAlgFamily
}

var jweKeyAlgorithms = map[string]jweKeyAlg{
	"dir":          {"dir", jweKeyAlgFamilyDir},
	"RSA-OAEP-256": {"RSA-OAEP-256", jweKeyAlgFamilyRSA},
}

var jweKeyAlgNames = []string{"dir", "RSA-OAEP-256"}

var jweKeyAlgorithmsLower = func() map[string]jweKeyAlg {
	m := make(map[string]jweKeyAlg, len(jweKeyAlgorithms))
	for _, alg := range jweKeyAlgorithms {
		m[strings.ToLower(alg.Name)] = alg
	}
	return m
}()

// lookupJWEKeyAlg resolves a user-supplied --alg flag value case-insensitively.
func lookupJWEKeyAlg(name string) (jweKeyAlg, bool) {
	alg, ok := jweKeyAlgorithmsLower[strings.ToLower(name)]
	return alg, ok
}

type jweEnc struct {
	Name    string
	KeySize int
	IVSize  int
	TagSize int
}

var jweEncAlgorithms = map[string]jweEnc{
	"A128GCM": {"A128GCM", 16, 12, 16},
	"A192GCM": {"A192GCM", 24, 12, 16},
	"A256GCM": {"A256GCM", 32, 12, 16},
}

var jweEncNames = []string{"A128GCM", "A192GCM", "A256GCM"}

var jweEncAlgorithmsLower = func() map[string]jweEnc {
	m := make(map[string]jweEnc, len(jweEncAlgorithms))
	for _, enc := range jweEncAlgorithms {
		m[strings.ToLower(enc.Name)] = enc
	}
	return m
}()

// lookupJWEEnc resolves a user-supplied --enc flag value case-insensitively.
func lookupJWEEnc(name string) (jweEnc, bool) {
	enc, ok := jweEncAlgorithmsLower[strings.ToLower(name)]
	return enc, ok
}

func addJWECommand(rootCmd *cobra.Command, o *Options) {
	var keyAlgName string
	var encAlgName string
	var kid string

	short := "Encrypt input as a JWE"
	if o.Decode {
		short = "Decrypt a JWE and decode its plaintext"
	}

	cmd := &cobra.Command{
		Use:   "jwe",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.Decode {
				return jweDecryptCmd(cmd, o, keyAlgName, encAlgName)
			}
			signKeyAlgName := keyAlgName
			if signKeyAlgName == "" {
				signKeyAlgName = "dir"
			}
			keyAlg, ok := lookupJWEKeyAlg(signKeyAlgName)
			if !ok {
				return fmt.Errorf("invalid %q flag %q: must be one of %v",
					"--"+FlagNameAlg, signKeyAlgName, strings.Join(jweKeyAlgNames, ", "))
			}
			signEncAlgName := encAlgName
			if signEncAlgName == "" {
				signEncAlgName = "A256GCM"
			}
			encAlg, ok := lookupJWEEnc(signEncAlgName)
			if !ok {
				return fmt.Errorf("invalid %q flag %q: must be one of %v",
					"--"+FlagNameEnc, signEncAlgName, strings.Join(jweEncNames, ", "))
			}
			return jweEncryptCmd(cmd, o, keyAlg, encAlg, kid)
		},
	}

	cmd.Flags().StringVarP(&keyAlgName, FlagNameAlg, "a", "",
		"key management algorithm: "+strings.Join(jweKeyAlgNames, ", ")+
			` (default "dir" when encrypting; when decrypting, taken from the token's "alg" header)`)
	cmd.Flags().StringVarP(&encAlgName, FlagNameEnc, "e", "",
		"content encryption algorithm: "+strings.Join(jweEncNames, ", ")+
			` (default "A256GCM" when encrypting; when decrypting, taken from the token's "enc" header)`)
	cmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "",
		"raw symmetric CEK filename (for alg=dir)")
	cmd.Flags().StringVar(&o.PrivateKeyFilename, FlagNamePrivateKey, "",
		"private key filename, for decrypting (RSA PKCS1 PEM for alg=RSA-OAEP-256)")
	cmd.Flags().StringVar(&o.PublicKeyFilename, FlagNamePublicKey, "",
		"public key filename, for encrypting (RSA PKCS1 PEM for alg=RSA-OAEP-256)")
	cmd.Flags().StringVar(&kid, FlagNameKid, "",
		"key ID to embed in the header; ignored when decrypting")
	cmd.Flags().BoolVarP(&o.AppendNewline, FlagNameAppendNewline, "n", o.AppendNewline,
		"append a trailing newline to the output")

	addJWEDumpCmd(cmd)

	rootCmd.AddCommand(cmd)
}

func jweEncryptCmd(cmd *cobra.Command, o *Options, keyAlg jweKeyAlg, encAlg jweEnc, kid string) error {
	warnIrrelevantJWEKeyFlags(keyAlg, o)

	var cek []byte
	var encryptedKey []byte
	switch keyAlg.Family {
	case jweKeyAlgFamilyDir:
		key, err := jweReadDirCEK(o, encAlg)
		if err != nil {
			return err
		}
		cek = key
	case jweKeyAlgFamilyRSA:
		publicKey, err := readRSAPublicKey(cmd, o)
		if err != nil {
			return err
		}
		cek = make([]byte, encAlg.KeySize)
		if _, err := io.ReadFull(rand.Reader, cek); err != nil {
			return fmt.Errorf("failed to generate CEK: %v", err)
		}
		encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, cek, nil)
		if err != nil {
			return fmt.Errorf("failed to wrap CEK: %v", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm %q", keyAlg.Name)
	}

	header := map[string]any{"alg": keyAlg.Name, "enc": encAlg.Name}
	if kid != "" {
		header["kid"] = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to encode header: %v", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	plaintext, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read plaintext from input: %v", err)
	}

	iv := make([]byte, encAlg.IVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}

	// AAD is always the ASCII bytes of the header's own base64url segment (RFC 7516 §5.1 step 14).
	aad := []byte(headerB64)
	ciphertext, tag, err := jweSealContent(cek, iv, plaintext, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt content: %v", err)
	}

	token := strings.Join([]string{
		headerB64,
		base64.RawURLEncoding.EncodeToString(encryptedKey),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, ".")

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

func jweDecryptCmd(cmd *cobra.Command, o *Options, keyAlgName, encAlgName string) error {
	input, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read token from input: %v", err)
	}
	token := strings.TrimSpace(string(input))
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return fmt.Errorf("invalid JWE: expected 5 dot-separated parts, got %v", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse header JSON: %v", err)
	}
	if header.Alg == "" || header.Enc == "" {
		return fmt.Errorf(`token header is missing required "alg"/"enc" fields (malformed or non-JWE token)`)
	}

	keyAlg, err := resolveJWEKeyAlg(keyAlgName, header.Alg)
	if err != nil {
		return err
	}
	encAlg, err := resolveJWEEnc(encAlgName, header.Enc)
	if err != nil {
		return err
	}

	warnIrrelevantJWEKeyFlags(keyAlg, o)

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode encrypted key: %v", err)
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode IV: %v", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode tag: %v", err)
	}

	var cek []byte
	switch keyAlg.Family {
	case jweKeyAlgFamilyDir:
		cek, err = jweReadDirCEK(o, encAlg)
	case jweKeyAlgFamilyRSA:
		var privateKey *rsa.PrivateKey
		privateKey, err = readRSAPrivateKey(cmd, o)
		if err == nil {
			cek, err = rsa.DecryptOAEP(sha256.New(), nil, privateKey, encryptedKey, nil)
		}
	default:
		err = fmt.Errorf("unsupported algorithm %q", keyAlg.Name)
	}
	if err != nil {
		return err
	}

	if len(cek) != encAlg.KeySize {
		return fmt.Errorf("CEK size %v bytes does not match %v requirement of %v bytes", len(cek), encAlg.Name, encAlg.KeySize)
	}

	plaintext, err := jweOpenContent(cek, iv, ciphertext, tag, []byte(parts[0]))
	if err != nil {
		return fmt.Errorf("content decryption failed: %v", err)
	}

	out := cmd.OutOrStdout()
	if _, err := out.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %v", err)
	}
	if o.AppendNewline {
		if _, err := io.WriteString(out, "\n"); err != nil {
			return fmt.Errorf("failed to append trailing newline: %v", err)
		}
	}
	return nil
}

func resolveJWEKeyAlg(flagValue, headerAlg string) (jweKeyAlg, error) {
	if flagValue != "" {
		alg, ok := lookupJWEKeyAlg(flagValue)
		if !ok {
			return jweKeyAlg{}, fmt.Errorf("invalid %q flag %q: must be one of %v",
				"--"+FlagNameAlg, flagValue, strings.Join(jweKeyAlgNames, ", "))
		}
		if headerAlg != alg.Name {
			return jweKeyAlg{}, fmt.Errorf("token alg %q does not match expected %v=%q", headerAlg, "--"+FlagNameAlg, alg.Name)
		}
		return alg, nil
	}
	alg, ok := jweKeyAlgorithms[headerAlg]
	if !ok {
		return jweKeyAlg{}, fmt.Errorf(`token has unsupported "alg" header %q: must be one of %v`,
			headerAlg, strings.Join(jweKeyAlgNames, ", "))
	}
	return alg, nil
}

func resolveJWEEnc(flagValue, headerEnc string) (jweEnc, error) {
	if flagValue != "" {
		enc, ok := lookupJWEEnc(flagValue)
		if !ok {
			return jweEnc{}, fmt.Errorf("invalid %q flag %q: must be one of %v",
				"--"+FlagNameEnc, flagValue, strings.Join(jweEncNames, ", "))
		}
		if headerEnc != enc.Name {
			return jweEnc{}, fmt.Errorf("token enc %q does not match expected %v=%q", headerEnc, "--"+FlagNameEnc, enc.Name)
		}
		return enc, nil
	}
	enc, ok := jweEncAlgorithms[headerEnc]
	if !ok {
		return jweEnc{}, fmt.Errorf(`token has unsupported "enc" header %q: must be one of %v`,
			headerEnc, strings.Join(jweEncNames, ", "))
	}
	return enc, nil
}

func warnIrrelevantJWEKeyFlags(keyAlg jweKeyAlg, o *Options) {
	switch keyAlg.Family {
	case jweKeyAlgFamilyDir:
		if o.PrivateKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for alg=dir", "--"+FlagNamePrivateKey)
		}
		if o.PublicKeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for alg=dir", "--"+FlagNamePublicKey)
		}
	case jweKeyAlgFamilyRSA:
		if o.KeyFilename != "" {
			log.Printf("WARNING: ignoring irrelevant %q flag for %v algorithms", "--"+FlagNameKey, keyAlg.Family)
		}
	}
}

func jweReadDirCEK(o *Options, encAlg jweEnc) ([]byte, error) {
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
	if len(key) != encAlg.KeySize {
		return nil, fmt.Errorf("invalid key size %v bytes for %v: must be exactly %v bytes",
			len(key), encAlg.Name, encAlg.KeySize)
	}
	return key, nil
}

func jweSealContent(cek, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	tagStart := len(sealed) - gcm.Overhead()
	return sealed[:tagStart], sealed[tagStart:], nil
}

func jweOpenContent(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, ciphertext...), tag...)
	return gcm.Open(nil, iv, sealed, aad)
}
