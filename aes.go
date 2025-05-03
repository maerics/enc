package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Decode {
				return aesDecrypt(cmd, o)
			}
			return aesEncrypt(cmd, o)
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

func aesDecrypt(cmd *cobra.Command, o *Options) error {
	// Determine the encryption mode.
	var decryptFunc func(cipher.Block, []byte, io.Writer, *Options) error
	switch o.AESMode {
	case aesModeBlock:
		decryptFunc = aesDecryptBlock
	case aesModeGCMAEAD:
		decryptFunc = aesDecryptGCMAEAD
	default:
		return fmt.Errorf("aes mode %q not implemented", o.AESMode)
	}

	// Read the decryption key.
	if o.KeyFilename == "" {
		return fmt.Errorf(`missing required "--%v" flag`, FlagNameKey)
	}
	keyReader := fileReader(cmd, FlagNameKey, o.KeyFilename, false)
	key, err := io.ReadAll(keyReader)
	if err != nil {
		return fmt.Errorf("failed to read all key bytes: %v", err)
	}
	o.KeyBytes = key

	// Generate the cipher.
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Read the ciphertext.
	ciphertextReader := cmd.InOrStdin()
	ciphertext, err := io.ReadAll(ciphertextReader)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %v", err)
	}

	// Decrypt and write the output.
	plaintextWriter := cmd.OutOrStdout()
	return decryptFunc(aesCipher, ciphertext, plaintextWriter, o)
}

func aesDecryptBlock(aesCipher cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	if len(o.KeyBytes) != len(ciphertext) {
		return fmt.Errorf("aes/decrypt: key size %vb != message size %vb", len(o.KeyBytes), len(ciphertext))
	}
	aesCipher.Decrypt(ciphertext, ciphertext)
	if _, err := plaintextWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

func aesDecryptGCMAEAD(aesCipher cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	// AES decrypt.
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	additionalData, err := readAdditionalData(o.AdditionalDataFilename)
	if err != nil {
		return nil
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[nonceSize:], additionalData)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if _, err := plaintextWriter.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %v", err)
	}
	return nil
}

func aesEncrypt(cmd *cobra.Command, o *Options) error {
	// Determine the encryption mode.
	var encryptFunc func(cipher.Block, []byte, io.Writer, *Options) error
	switch o.AESMode {
	case aesModeBlock:
		encryptFunc = aesEncryptBlock
	case aesModeGCMAEAD:
		encryptFunc = aesEncryptGCMAEAD
	default:
		return fmt.Errorf("aes mode %q not implemented", o.AESMode)
	}

	// Read the encryption key.
	if o.KeyFilename == "" {
		return fmt.Errorf(`missing required "--%v" flag`, FlagNameKey)
	}
	keyReader := fileReader(cmd, FlagNameKey, o.KeyFilename, false)
	key, err := io.ReadAll(keyReader)
	if err != nil {
		return fmt.Errorf("failed to read all key bytes: %v", err)
	}
	o.KeyBytes = key

	// Generate the cipher.
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Read the plaintext.
	plaintextReader := cmd.InOrStdin()
	plaintext, err := io.ReadAll(plaintextReader)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %v", err)
	}

	// Encrypt and write the output.
	ciphertextWriter := cmd.OutOrStdout()
	return encryptFunc(aesCipher, plaintext, ciphertextWriter, o)
}

func aesEncryptBlock(aesCipher cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	if len(o.KeyBytes) != len(plaintext) {
		return fmt.Errorf("aes/encrypt: key size %vb != input size %vb", len(o.KeyBytes), len(plaintext))
	}
	aesCipher.Encrypt(plaintext, plaintext)
	if _, err := ciphertextWriter.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

func aesEncryptGCMAEAD(aesCipher cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("failed to create new GCM AEAD: %v", err)
	}
	nonceSize := aesgcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce of size %v: %v", nonceSize, err)
	}
	additionalData, err := readAdditionalData(o.AdditionalDataFilename)
	if err != nil {
		return err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalData)
	if _, err := ciphertextWriter.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %v", err)
	}
	if _, err := ciphertextWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

func readAdditionalData(filename string) ([]byte, error) {
	if filename != "" {
		bs, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read additional data from %q: %v", filename, err)
		}
		return bs, nil
	}
	return nil, nil
}
