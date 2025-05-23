package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"testing"
)

var knownErrors = map[string]func(algo, mode string, key, message, iv, ad []byte) error{
	"aes": func(algo, mode string, key, message, iv, ad []byte) error {
		switch true {
		case mode == string(cryptoModeCBC):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeCBC))
		case mode == string(cryptoModeCFB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeCFB))
		case mode == string(cryptoModeECB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeECB))
		case mode == string(cryptoModeOFB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeOFB))
		case !find(len(key), 16, 24, 32): // Key size must be {16,24,32}
			return fmt.Errorf("failed to create AES cipher: crypto/aes: invalid key size %v", len(key))
		case mode == string(cryptoModeBlock) && len(message) != len(key):
			return fmt.Errorf("AES/encrypt: key size %vb != input size %vb", len(key), len(message))
		case mode == string(cryptoModeCTR) && len(iv) > 0 && len(iv) != aes.BlockSize:
			return fmt.Errorf("invalid initialization vector size %v for block size %v", len(iv), aes.BlockSize)
		}
		return nil
	},
	"des": func(algo, mode string, key, message, iv, ad []byte) error {
		switch true {
		case len(ad) > 0:
			return fmt.Errorf("unknown flag: --additional-data")
		case mode == string(cryptoModeCBC):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeCBC))
		case mode == string(cryptoModeCFB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeCFB))
		case mode == string(cryptoModeECB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeECB))
		case mode == string(cryptoModeOFB):
			return fmt.Errorf("mode %q not implemented", string(cryptoModeOFB))
		case len(key) != 8: // Key size must be 8
			return fmt.Errorf("failed to create DES cipher: crypto/des: invalid key size %v", len(key))
		case mode == string(cryptoModeGCM):
			return fmt.Errorf("failed to initialize GCM AEAD mode: cipher: NewGCM requires 128-bit block cipher")
		case mode == string(cryptoModeBlock) && len(message) != len(key):
			return fmt.Errorf("DES/encrypt: key size 8b != input size %vb", len(message))
		case mode == string(cryptoModeCTR) && len(iv) > 0 && len(iv) != len(key):
			return fmt.Errorf("invalid initialization vector size %v for block size 8", len(iv))
		}
		return nil
	},
}

func TestSymmetricCrypto(t *testing.T) {
	for _, key := range testKeys {
		for _, message := range testMessages {
			for _, iv := range testIVs {
				for _, ad := range testAdditionalDatas {
					for _, mode := range AllCryptoModeStrings {
						for algo, knownAlgoErrors := range knownErrors {
							// Prepare the input files.
							keyFilename := path.Join(os.TempDir(), fmt.Sprintf("key-%v.key", len(key)))
							mustWrite(t, keyFilename, key)
							ivFilename := path.Join(os.TempDir(), fmt.Sprintf("iv-%v.dat", len(iv)))
							mustWrite(t, ivFilename, iv)
							adFilename := path.Join(os.TempDir(), fmt.Sprintf("ad-%v.dat", len(ad)))
							mustWrite(t, adFilename, ad)

							// Find the expected error.
							args := []string{algo, "--mode", string(mode), "--key", keyFilename}
							if iv != nil {
								args = append(args, "--iv", ivFilename)
							}
							if ad != nil {
								args = append(args, "--additional-data", adFilename)
							}
							expectedErr := knownAlgoErrors(algo, mode, key, message, iv, ad)

							// Encrypt.
							encryptCmd := newEncCmd(getDefaultOptions())
							encryptCmd.SetArgs(args)
							encryptCmd.SetIn(bytes.NewReader(message))
							encryptStdout := new(bytes.Buffer)
							encryptCmd.SetOut(encryptStdout)
							encryptErr := encryptCmd.Execute()
							encryptedBytes := encryptStdout.Bytes()
							if encryptErr != nil {
								if expectedErr == nil {
									t.Fatalf("unexpected encryption error: args=%#v, actual err=%v",
										args, encryptErr)
								} else if encryptErr.Error() != expectedErr.Error() {
									t.Fatalf("encryption error: args=%#v\nwanted %q\nactual %q",
										args, expectedErr.Error(), encryptErr.Error())
								} else {
									continue
								}
							} else if expectedErr != nil {
								t.Fatalf("unexpected encryption success: args=%#v, expected err=%v", args, expectedErr)
							}

							// Decrypt.
							decryptCmd := newEncCmd(getDefaultOptions())
							decryptCmd.SetArgs(append(args, "--decrypt"))
							decryptCmd.SetIn(bytes.NewReader(encryptedBytes))
							decryptStdout := new(bytes.Buffer)
							decryptCmd.SetOut(decryptStdout)
							decryptErr := decryptCmd.Execute()
							plaintextBytes := decryptStdout.Bytes()
							if decryptErr != nil {
								if expectedErr == nil {
									t.Fatalf("unexpected decryption error: args=%#v, err=%v", args, decryptErr)
								} else if encryptErr.Error() != expectedErr.Error() {
									t.Fatalf("decryption error: args=%#v\nwanted %q\nactual %q", args, expectedErr.Error(), encryptErr.Error())
								} else {
									continue
								}
							}

							// Check for error or equality.
							roundTripOK := reflect.DeepEqual(message, plaintextBytes)
							if !roundTripOK {
								t.Fatalf("roundtrip failed: args=%#v\nwanted %q (%#v)\nactual %q (%#v)",
									args, string(message), message, string(plaintextBytes), plaintextBytes)
							} else if expectedErr != nil {
								t.Fatalf("unexpected roundtrip success: args=%#v, expected error %v", args, expectedErr)
							}
						}
					}
				}
			}
		}
	}
}

var testKeys = [][]byte{
	mustRand(8),
	mustRand(16),
	mustRand(24),
	mustRand(32),
}

var testMessages = [][]byte{
	// -- 64bit (8byte) message boundaries
	[]byte("secret!"),    // 7byte
	[]byte("secret!\n"),  // 8byte
	[]byte("secret!?\n"), // 9byte
	// -- 128bit (16byte) message boundaries
	[]byte("Hello, World!!\n"),   // 15byte
	[]byte("Hello, World!!!\n"),  // 16byte
	[]byte("Hello, World!!!!\n"), // 17byte
	// -- 192bit (24byte) message boundaries
	[]byte("Reality called I hung u"),    // 23byte
	[]byte("Reality called I hung up"),   // 24byte
	[]byte("Reality called I hung up\n"), // 25byte
	// -- 256bit (32byte) message boundaries
	[]byte("This is a test of the emergenc"),    // 31byte
	[]byte("This is a test of the emergency"),   // 32byte
	[]byte("This is a test of the emergency\n"), // 33byte
}

var testIVs = [][]byte{
	nil,
	make([]byte, 8),
	make([]byte, 16),
	make([]byte, 24),
	make([]byte, 32),
}

var testAdditionalDatas = [][]byte{
	nil,
	mustRand(8),
}

func mustWrite(t *testing.T, filename string, bs []byte) {
	if err := os.WriteFile(filename, bs, os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
}

func mustRand(n int) []byte {
	bs := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bs); err != nil {
		panic(err)
	}
	return bs
}

func find[T comparable](needle T, haystack ...T) bool {
	for _, x := range haystack {
		if x == needle {
			return true
		}
	}
	return false
}
