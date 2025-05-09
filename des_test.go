package main

import (
	"bytes"
	"fmt"
	"path"
	"reflect"
	"strings"
	"testing"
)

func TestDESEndToEnd(t *testing.T) {
	algos := []string{"des", "3des"}
	modes := []string{"block"}

	keys := [][]byte{
		mustRand(t, 8),
		mustRand(t, 16),
		mustRand(t, 24),
		mustRand(t, 32),
	}

	messages := [][]byte{
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

	examples := []func(algo, mode string, key, message []byte) error{
		func(algo, mode string, key, message []byte) error {
			switch true {
			// DES
			case algo == "des" && len(key) != 8:
				return fmt.Errorf("failed to create DES cipher: crypto/des: invalid key size %v", len(key))
			case algo == "des" && mode == "block" && len(message) != 8:
				return fmt.Errorf("%v/encrypt: key size %vb != input size %vb", strings.ToUpper(algo), len(key), len(message))
			case algo == "des" && mode == "block" && len(message) == 8:
				return nil
			// 3DES
			case algo == "3des" && len(key) != 24:
				return fmt.Errorf("failed to create 3DES cipher: crypto/des: invalid key size %v", len(key))
			case algo == "3des" && mode == "block" && len(message) != 24:
				return fmt.Errorf("%v/encrypt: key size %vb != input size %vb", strings.ToUpper(algo), len(key), len(message))
			case algo == "3des" && mode == "block" && len(message) == 24:
				return nil
			}
			panic(fmt.Sprintf("what do? %v/%v k%v m%v", algo, mode, len(key), len(message)))
		},
	}

	for _, algo := range algos {
		for _, mode := range modes {
			for _, key := range keys {
				for _, message := range messages {
					for _, errorFunc := range examples {
						expectedErr := errorFunc(algo, mode, key, message)

						// DES encrypt.
						keyFilename := path.Join(t.TempDir(), fmt.Sprintf("%v-ks%v-ms%v.key", algo, len(key), len(message)))
						mustWrite(t, keyFilename, key)
						desEncryptCmd := newEncCmd(getDefaultOptions())
						desEncryptCmd.SetArgs([]string{algo, "--mode", string(mode), "--key", keyFilename})
						desEncryptCmd.SetIn(bytes.NewReader(message))
						encryptStdout := new(bytes.Buffer)
						desEncryptCmd.SetOut(encryptStdout)
						encryptErr := desEncryptCmd.Execute()
						encryptedBytes := encryptStdout.Bytes()
						if encryptErr != nil {
							if expectedErr == nil {
								t.Fatalf("unexpected encryption error: algo=%v, mode=%v, k%v, m%v, actual err=%v",
									algo, mode, len(key), len(message), encryptErr)
							} else if encryptErr.Error() != expectedErr.Error() {
								t.Fatalf("encryption error: algo=%v, mode=%v, k%v, m%v\nwanted %q\nactual %q",
									algo, mode, len(key), len(message), expectedErr.Error(), encryptErr.Error())
							} else {
								continue
							}
						} else if expectedErr != nil {
							t.Fatalf("unexpected encryption success: mode=%v, k%v, m%v, expected err=%v",
								mode, len(key), len(message), expectedErr)
						}

						// DES decrypt.
						desDecryptCmd := newEncCmd(getDefaultOptions())
						desDecryptCmd.SetArgs([]string{algo, "--decrypt", "--mode", string(mode), "--key", keyFilename})
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
								t.Fatalf("decryption error: mode=%v, k%v, m%v\nwanted %q\nactual %q",
									mode, len(key), len(message), expectedErr.Error(), encryptErr.Error())
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
}
