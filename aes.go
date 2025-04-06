package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"

	"github.com/spf13/cobra"
)

func addAesCommands(rootCmd *cobra.Command, o *Options) {
	short := "Encrypt data using AES"
	if o.Decode {
		short = "Decrypt data using AES"
	}

	aesCmd := &cobra.Command{
		Use:   "aes",
		Short: short,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if o.Decode {
				aesDecrypt(cmd, o)
				return
			}
			aesEncrypt(cmd, o)
		},
	}

	aesCmd.Flags().BoolVarP(&o.Decode, "decrypt", "d", o.Decode, "AES decrypt")
	aesCmd.Flags().StringVarP(&o.KeyFilename, "key", "k", "", "key filename")

	rootCmd.AddCommand(aesCmd)
}

func aesDecrypt(cmd *cobra.Command, o *Options) {
	// Read the decryption key.
	keyReader := fileReader(cmd, "key", o.KeyFilename, false)
	key, err := io.ReadAll(keyReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read all key bytes: %v", err)
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("FATAL: failed to create AES cipher: %v", err)
	}

	// Read the ciphertext.
	ciphertextReader := cmd.InOrStdin()
	ciphertext, err := io.ReadAll(ciphertextReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read plaintext: %v", err)
	}

	// AES decrypt.
	plaintextWriter := cmd.OutOrStdout()
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatalf("FATAL: failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	if _, err := plaintextWriter.Write(plaintext); err != nil {
		log.Fatalf("FATAL: failed to write plaintext: %v", err)
	}

}

func aesEncrypt(cmd *cobra.Command, o *Options) {
	// Read the encryption key.
	keyReader := fileReader(cmd, "key", o.KeyFilename, false)
	key, err := io.ReadAll(keyReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read all key bytes: %v", err)
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("FATAL: failed to create AES cipher: %v", err)
	}

	// Read the plaintext.
	plaintextReader := cmd.InOrStdin()
	plaintext, err := io.ReadAll(plaintextReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read plaintext: %v", err)
	}

	// AES encrypt.
	ciphertextWriter := cmd.OutOrStdout()
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatalf("FATAL: failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("FATAL: failed to generate nonce of size %v: %v", nonceSize, err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	if _, err := ciphertextWriter.Write(nonce); err != nil {
		log.Fatalf("FATAL: failed to write nonce: %v", err)
	}
	if _, err := ciphertextWriter.Write(ciphertext); err != nil {
		log.Fatalf("FATAL: failed to write ciphertext: %v", err)
	}
}
