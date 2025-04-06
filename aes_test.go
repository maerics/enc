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
		[]byte("Hello, AES!\n"),
		mustRead(t, "go.sum"),
		// TODO: a bunch of random bytes.
	}

	for i, eg := range []struct {
		key []byte
	}{
		{mustRand(t, 16)},
		{mustRand(t, 24)},
		{mustRand(t, 32)},
	} {
		for _, message := range messages {
			// AES encrypt.
			keyFilename := path.Join(t.TempDir(), fmt.Sprintf("aes-ks%v-ms%v.key", len(eg.key), len(message)))
			mustWrite(t, keyFilename, eg.key)
			aesEncryptCmd := newEncCmd(getDefaultOptions())
			aesEncryptCmd.SetArgs([]string{"aes", "-k", keyFilename})
			aesEncryptCmd.SetIn(bytes.NewReader(message))
			encryptStdout := new(bytes.Buffer)
			aesEncryptCmd.SetOut(encryptStdout)
			aesEncryptCmd.Execute()
			ciphertextBytes := encryptStdout.Bytes()

			// AES decrypt.
			aesDecryptCmd := newEncCmd(getDefaultOptions())
			aesDecryptCmd.SetArgs([]string{"aes", "-d", "-k", keyFilename})
			aesDecryptCmd.SetIn(bytes.NewReader(ciphertextBytes))
			decryptStdout := new(bytes.Buffer)
			aesDecryptCmd.SetOut(decryptStdout)
			aesDecryptCmd.Execute()
			plaintextBytes := decryptStdout.Bytes()

			if !reflect.DeepEqual(message, plaintextBytes) {
				t.Fatalf("example %v decryption failed\nwanted %v\n   got %v", i, message, plaintextBytes)
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
