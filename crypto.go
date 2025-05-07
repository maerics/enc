package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Encryption.
func encrypt(cmd *cobra.Command, o *Options, cipherName string, cipherFunc func([]byte) (cipher.Block, error)) error {
	// Determine the encryption mode.
	var encryptFunc func(string, cipher.Block, []byte, io.Writer, *Options) error
	switch o.CryptoMode {
	case cryptoModeBlock:
		encryptFunc = encryptBlock
	case cryptoModeGCMAEAD:
		encryptFunc = encryptGCMAEAD
	default:
		return fmt.Errorf("mode %q not implemented", o.CryptoMode)
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
	c, err := cipherFunc(key)
	if err != nil {
		return fmt.Errorf("failed to create %v cipher: %v", cipherName, err)
	}

	// Read the plaintext.
	plaintextReader := cmd.InOrStdin()
	plaintext, err := io.ReadAll(plaintextReader)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %v", err)
	}

	// Encrypt and write the output.
	ciphertextWriter := cmd.OutOrStdout()
	return encryptFunc(cipherName, c, plaintext, ciphertextWriter, o)
}

// Decryption.
func decrypt(cmd *cobra.Command, o *Options, cipherName string, cipherFunc func([]byte) (cipher.Block, error)) error {
	// Determine the encryption mode.
	var decryptFunc func(string, cipher.Block, []byte, io.Writer, *Options) error
	switch o.CryptoMode {
	case cryptoModeBlock:
		decryptFunc = decryptBlock
	case cryptoModeGCMAEAD:
		decryptFunc = decryptGCMAEAD
	default:
		return fmt.Errorf("mode %q not implemented", o.CryptoMode)
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
	c, err := cipherFunc(key)
	if err != nil {
		return fmt.Errorf("failed to create %v cipher: %v", cipherName, err)
	}

	// Read the ciphertext.
	ciphertextReader := cmd.InOrStdin()
	ciphertext, err := io.ReadAll(ciphertextReader)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %v", err)
	}

	// Decrypt and write the output.
	plaintextWriter := cmd.OutOrStdout()
	return decryptFunc(cipherName, c, ciphertext, plaintextWriter, o)
}

// Block mode encryption.
func encryptBlock(cipherName string, c cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	if len(o.KeyBytes) != len(plaintext) {
		return fmt.Errorf("%v/encrypt: key size %vb != input size %vb", cipherName, len(o.KeyBytes), len(plaintext))
	}
	c.Encrypt(plaintext, plaintext)
	if _, err := ciphertextWriter.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

// Block mode decryption.
func decryptBlock(cipherName string, c cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	if len(o.KeyBytes) != len(ciphertext) {
		return fmt.Errorf("%v/decrypt: key size %vb != message size %vb", cipherName, len(o.KeyBytes), len(ciphertext))
	}
	c.Decrypt(ciphertext, ciphertext)
	if _, err := plaintextWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

// GCM AEAD mode encryption.
func encryptGCMAEAD(cipherName string, c cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("failed to create new GCM AEAD: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce of size %v: %v", nonceSize, err)
	}
	additionalData, err := readAdditionalData(o.AdditionalDataFilename)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
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

// GCM AEAD mode decryption.
func decryptGCMAEAD(cipherName string, c cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("failed to create new GCM AEAD: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	additionalData, err := readAdditionalData(o.AdditionalDataFilename)
	if err != nil {
		return nil
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], additionalData)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if _, err := plaintextWriter.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %v", err)
	}
	return nil
}
