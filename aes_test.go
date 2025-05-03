package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"testing"
)

func TestAesEndToEnd(t *testing.T) {
	messages := [][]byte{
		// -- 128bit (16byte) message boundaries
		[]byte("Hello, World!!\n"),   // 15byte
		[]byte("Hello, World!!!\n"),  // 16byte
		[]byte("Hello, World!!!!\n"), // 17byte
		// -- 192bit (24byte) message boundaries
		[]byte("Reality called I hung u"),    // 23byte
		[]byte("Reality called I hung up"),   // 23byte
		[]byte("Reality called I hung up\n"), // 23byte
		// -- 256bit (32byte) message boundaries
		[]byte("This is a test of the emergenc"),    // 31byte
		[]byte("This is a test of the emergency"),   // 32byte
		[]byte("This is a test of the emergency\n"), // 33byte
	}

	keys := [][]byte{
		mustRand(t, 16),
		mustRand(t, 24),
		mustRand(t, 32),
	}

	examples := map[aesMode][]func(message, key []byte) error{
		aesModeBlock: {
			func(message, key []byte) error {
				if len(message) != len(key) {
					return fmt.Errorf("aes/encrypt: key size %vb != input size %vb", len(key), len(message))
				}
				return nil
			},
		},
	}

	for _, message := range messages {
		for _, key := range keys {
			for mode, errorFuncs := range examples {
				for _, errorFunc := range errorFuncs {
					expectedErr := errorFunc(message, key)

					// AES encrypt.
					keyFilename := path.Join(t.TempDir(), fmt.Sprintf("aes-ks%v-ms%v.key", len(key), len(message)))
					mustWrite(t, keyFilename, key)
					aesEncryptCmd := newEncCmd(getDefaultOptions())
					aesEncryptCmd.SetArgs([]string{"aes", "--mode", string(mode), "--key", keyFilename})
					aesEncryptCmd.SetIn(bytes.NewReader(message))
					encryptStdout := new(bytes.Buffer)
					aesEncryptCmd.SetOut(encryptStdout)
					encryptErr := aesEncryptCmd.Execute()
					encryptedBytes := encryptStdout.Bytes()
					if encryptErr != nil {
						if expectedErr == nil {
							t.Fatalf("unexpected encryption error: mode=%v, k%v, m%v, actual err=%v",
								mode, len(key), len(message), encryptErr)
						} else if encryptErr.Error() != expectedErr.Error() {
							t.Fatalf("encryption error: mode=%v, k%v, m%v\nwanted %v\nactual %v",
								mode, len(key), len(message), expectedErr, encryptErr)
						} else {
							continue
						}
					} else if expectedErr != nil {
						t.Fatalf("unexpected encryption success: mode=%v, k%v, m%v, expected err=%v",
							mode, len(key), len(message), expectedErr)
					}

					// AES decrypt.
					aesDecryptCmd := newEncCmd(getDefaultOptions())
					aesDecryptCmd.SetArgs([]string{"aes", "--decrypt", "--mode", string(mode), "--key", keyFilename})
					aesDecryptCmd.SetIn(bytes.NewReader(encryptedBytes))
					decryptStdout := new(bytes.Buffer)
					aesDecryptCmd.SetOut(decryptStdout)
					decryptErr := aesDecryptCmd.Execute() // TODO
					plaintextBytes := decryptStdout.Bytes()
					if decryptErr != nil {
						if expectedErr == nil {
							t.Fatalf("unexpected decryption error: mode=%v, k%v, m%v, err=%v",
								mode, len(key), len(message), decryptErr)
						} else if encryptErr.Error() != expectedErr.Error() {
							t.Fatalf("decryption error: mode=%v, k%v, m%v\nwanted %v\nactual %v",
								mode, len(key), len(message), expectedErr, encryptErr)
						} else {
							continue
						}
					}

					// Check for error or equality.
					roundTripOK := reflect.DeepEqual(message, plaintextBytes)
					if !roundTripOK {
						t.Fatalf("roundtrip failed: mode=%v k%v m%v\nwanted %q\nactual %q",
							mode, len(key), len(message), string(message), string(plaintextBytes))
					} else if expectedErr != nil {
						t.Fatalf("unexpected roundtrip success: mode=%v k%v m%v, expected error %v",
							mode, len(key), len(message), expectedErr)
					}
				}
			}
		}
	}
}

func mustRead(t *testing.T, filename string) []byte {
	bs, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func mustWrite(t *testing.T, filename string, bs []byte) {
	if err := os.WriteFile(filename, bs, os.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
}

func mustRand(t *testing.T, n int) []byte {
	bs := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bs); err != nil {
		t.Fatal(err)
	}
	return bs
}
