package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

const (
	CipherNameAES       = "AES"
	CipherNameDES       = "DES"
	CipherNameTRIPLEDES = "3DES"
)

func addSymmetricCryptoCommands(rootCmd *cobra.Command, o *Options) {
	type cryptoSymCmdInfo struct {
		cmdName     string
		cipherName  string
		cipherFunc  func([]byte) (cipher.Block, error)
		aliases     []string
		defaultMode cryptoMode
	}

	for _, algo := range []cryptoSymCmdInfo{
		{"aes", CipherNameAES, aes.NewCipher, nil, cryptoModeGCM},
		{"des", CipherNameDES, des.NewCipher, nil, cryptoModeCTR},
		{"des3", CipherNameTRIPLEDES, des.NewTripleDESCipher, []string{"3des", "tripledes", "triple-des"}, cryptoModeCTR},
	} {
		(func(cmdInfo cryptoSymCmdInfo) {
			short := "Encrypt input using " + cmdInfo.cipherName
			if o.Decode {
				short = "Decrypt input using " + cmdInfo.cipherName
			}

			symCryptoCmd := &cobra.Command{
				Use:     cmdInfo.cmdName,
				Short:   short,
				Args:    cobra.NoArgs,
				Aliases: cmdInfo.aliases,
				PreRun: func(cmd *cobra.Command, args []string) {
					if o.CryptoMode == "" {
						o.CryptoMode = cmdInfo.defaultMode
					}
				},
				RunE: func(cmd *cobra.Command, _ []string) error {
					if o.Decode {
						return decrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
					}
					return encrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
				},
			}

			symCryptoCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")

			// TODO: selective modes and IV args?
			symCryptoCmd.Flags().StringVarP(&o.InitializationVectorFilename, FlagNameIV, "", "", "initialization vector filename")
			symCryptoCmd.Flags().VarP(&o.CryptoMode, "mode", "m", o.EncryptionModeString()+" mode: "+cryptoModesString)

			if algo.cmdName == "aes" {
				symCryptoCmd.Flags().StringVarP(&o.AdditionalDataFilename, "additional-data", "a", "",
					fmt.Sprintf("additional data filename for %q mode", cryptoModeGCM))
			}

			rootCmd.AddCommand(symCryptoCmd)
		})(algo)
	}
}

// Encryption.
func encrypt(cmd *cobra.Command, o *Options, cipherName string, cipherFunc func([]byte) (cipher.Block, error)) error {
	// Determine the encryption mode.
	var encryptFunc func(string, cipher.Block, []byte, io.Writer, *Options) error
	switch o.CryptoMode {
	case cryptoModeBlock:
		encryptFunc = encryptBlock
	case cryptoModeCTR:
		encryptFunc = encryptCTR
	case cryptoModeGCM:
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
	case cryptoModeCTR:
		decryptFunc = decryptCTR
	case cryptoModeGCM:
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

// CTR mode encryption.
func encryptCTR(cipherName string, c cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	ciphertext := make([]byte, c.BlockSize()+len(plaintext))
	iv := ciphertext[:c.BlockSize()]
	if o.InitializationVectorFilename != "" {
		// TODO: file open?
		bs, err := os.ReadFile(o.InitializationVectorFilename)
		if err != nil {
			return fmt.Errorf(`failed to read "iv" file for reading: %v`, err)
		}
		if len(iv) != len(bs) {
			return fmt.Errorf("invalid initialization vector size %v for block size %v", len(bs), len(iv))
		}
		copy(iv, bs)
	} else if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	stream := cipher.NewCTR(c, iv)
	stream.XORKeyStream(ciphertext[c.BlockSize():], plaintext)
	if _, err := ciphertextWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

// CTR mode encryption.
func decryptCTR(cipherName string, c cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	// TODO: warn if given IV flag?
	iv := ciphertext[:c.BlockSize()]
	plaintext := ciphertext[c.BlockSize():]
	stream := cipher.NewCTR(c, iv)
	stream.XORKeyStream(plaintext, ciphertext[c.BlockSize():])
	if _, err := plaintextWriter.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %v", err)
	}
	return nil
}

// GCM AEAD mode encryption.
func encryptGCMAEAD(cipherName string, c cipher.Block, plaintext []byte, ciphertextWriter io.Writer, o *Options) error {
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return fmt.Errorf("failed to initialize GCM AEAD mode: %v", err)
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
