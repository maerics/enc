package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

func addAesCommands(rootCmd *cobra.Command, o *Options) {
	o.AESMode = aesModeGCMAEAD
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

	aesCmd.Flags().BoolVarP(&o.Decode, "decrypt", "d", o.Decode, "decrypt")
	aesCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")
	aesCmd.Flags().StringVarP(&o.AdditionalDataFilename, "additional-data", "", "",
		fmt.Sprintf("additional data for %q mode", aesModeGCMAEAD))

	// TODO
	// --mode={block,cbc,ecb,gcm-aead,...}
	// --block (shorthand for "--mode=block")
	// --cbc (shorthand for "--mode=cbc")
	// --ecb (shorthand for "--mode=ecb")
	// --gcm-aead (shorthand for "--mode=gcm-aead" [default])
	aesCmd.Flags().Var(&o.AESMode, "mode", "encryption mode, allowed: "+aesModesString)

	rootCmd.AddCommand(aesCmd)
}

func aesDecrypt(cmd *cobra.Command, o *Options) {
	// Read the decryption key.
	if o.KeyFilename == "" {
		log.Fatalf(`FATAL: missing required "--%v" flag`, FlagNameKey)
	}
	keyReader := fileReader(cmd, FlagNameKey, o.KeyFilename, false)
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
	plaintextWriter := cmd.OutOrStdout()

	switch o.AESMode {
	case aesModeBlock:
		aesDecryptBlock(aesCipher, ciphertext, plaintextWriter, o)
	case aesModeGCMAEAD:
		aesDecryptGCMAEAD(aesCipher, ciphertext, plaintextWriter, o)
	default:
		log.Fatalf("AES mode %q: not implemented", o.AESMode)
	}
}

func aesDecryptBlock(aesCipher cipher.Block, ciphertext []byte, plaintextWriter io.Writer, _ *Options) {
	if aesCipher.BlockSize()%len(ciphertext) != 0 {
		log.Fatalf("aes/encrypt: Key size %vb != input size %vb", aesCipher.BlockSize(), len(ciphertext))
	}
	aesCipher.Decrypt(ciphertext, ciphertext)
	if _, err := plaintextWriter.Write(ciphertext); err != nil {
		log.Fatalf("FATAL: failed to write ciphertext: %v", err)
	}
}

func aesDecryptGCMAEAD(aesCipher cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) {
	// AES decrypt.
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatalf("FATAL: failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	additionalData := readAdditionalData(o.AdditionalDataFilename)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[nonceSize:], additionalData)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	if _, err := plaintextWriter.Write(plaintext); err != nil {
		log.Fatalf("FATAL: failed to write plaintext: %v", err)
	}
}

func aesEncrypt(cmd *cobra.Command, o *Options) {
	// Read the encryption key.
	if o.KeyFilename == "" {
		log.Fatalf(`FATAL: missing required "--%v" flag`, FlagNameKey)
	}
	keyReader := fileReader(cmd, FlagNameKey, o.KeyFilename, false)
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

	ciphertextWriter := cmd.OutOrStdout()
	switch o.AESMode {
	case aesModeBlock:
		aesEncryptBlock(aesCipher, plaintext, ciphertextWriter, o)
	case aesModeGCMAEAD:
		aesEncryptGCMAEAD(aesCipher, plaintext, ciphertextWriter, o)
	default:
		log.Fatalf("AES mode %q: not implemented", o.AESMode)
	}
}

func aesEncryptBlock(aesCipher cipher.Block, plaintext []byte, ciphertextWriter io.Writer, _ *Options) {
	if aesCipher.BlockSize()%len(plaintext) != 0 {
		log.Fatalf("aes/encrypt: key size %vb != input size %vb", aesCipher.BlockSize(), len(plaintext))
	}
	aesCipher.Encrypt(plaintext, plaintext)
	if _, err := ciphertextWriter.Write(plaintext); err != nil {
		log.Fatalf("FATAL: failed to write ciphertext: %v", err)
	}
}

func aesEncryptGCMAEAD(aesCipher cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) {
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatalf("FATAL: failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("FATAL: failed to generate nonce of size %v: %v", nonceSize, err)
	}
	additionalData := readAdditionalData(o.AdditionalDataFilename)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalData)
	if _, err := ciphertextWriter.Write(nonce); err != nil {
		log.Fatalf("FATAL: failed to write nonce: %v", err)
	}
	if _, err := ciphertextWriter.Write(ciphertext); err != nil {
		log.Fatalf("FATAL: failed to write ciphertext: %v", err)
	}
}

func readAdditionalData(filename string) []byte {
	if filename != "" {
		bs, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("FATAL: failed to read additional data from %q: %v", filename, err)
		}
		return bs
	}
	return nil
}
