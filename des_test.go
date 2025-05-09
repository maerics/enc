package main

import (
	"bytes"
	"fmt"
	"path"
	"reflect"
	"testing"
)

func TestDESEndToEnd(t *testing.T) {
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
		mustRand(t, 8),
	}

	examples := map[cryptoMode][]func(message, key []byte) error{
		cryptoModeBlock: {
			func(message, key []byte) error {
				if len(message) != len(key) {
					return fmt.Errorf("DES/encrypt: key size %vb != input size %vb", len(key), len(message))
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

					// DES encrypt.
					keyFilename := path.Join(t.TempDir(), fmt.Sprintf("des-ks%v-ms%v.key", len(key), len(message)))
					mustWrite(t, keyFilename, key)
					desEncryptCmd := newEncCmd(getDefaultOptions())
					desEncryptCmd.SetArgs([]string{"des", "--mode", string(mode), "--key", keyFilename})
					desEncryptCmd.SetIn(bytes.NewReader(message))
					encryptStdout := new(bytes.Buffer)
					desEncryptCmd.SetOut(encryptStdout)
					encryptErr := desEncryptCmd.Execute()
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

					// DES decrypt.
					desDecryptCmd := newEncCmd(getDefaultOptions())
					desDecryptCmd.SetArgs([]string{"des", "--decrypt", "--mode", string(mode), "--key", keyFilename})
					desDecryptCmd.SetIn(bytes.NewReader(encryptedBytes))
					decryptStdout := new(bytes.Buffer)
					desDecryptCmd.SetOut(decryptStdout)
					decryptErr := desDecryptCmd.Execute()
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
