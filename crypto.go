package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
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

	for _, cmdInfo := range []cryptoSymCmdInfo{
		{"aes", CipherNameAES, aes.NewCipher, nil, cryptoModeGCM},
		{"des", CipherNameDES, des.NewCipher, nil, cryptoModeCTR},
		{"des3", CipherNameTRIPLEDES, des.NewTripleDESCipher, []string{"3des", "tripledes", "triple-des"}, cryptoModeCTR},
	} {
		short := "Encrypt input using " + cmdInfo.cipherName
		if o.Decode {
			short = "Decrypt input using " + cmdInfo.cipherName
		}

		activeCryptoMode := cmdInfo.defaultMode

		cryptoCmd := &cobra.Command{
			Use:     cmdInfo.cmdName,
			Short:   short,
			Args:    cobra.NoArgs,
			Aliases: cmdInfo.aliases,
			PreRun: func(cmd *cobra.Command, args []string) {
				o.CryptoMode = activeCryptoMode
			},
			RunE: func(cmd *cobra.Command, _ []string) error {
				if o.Decode {
					return decrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
				}
				return encrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
			},
		}

		cryptoCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")
		cryptoCmd.Flags().VarP(&activeCryptoMode, "mode", "m", o.EncryptionModeString()+" mode: "+cryptoModesString)

		cryptoCmd.Flags().StringVarP(&o.InitializationVectorFilename, FlagNameIV, "",
			o.InitializationVectorFilename, "initialization vector filename")
		cryptoCmd.Flags().BoolVarP(&o.OmitInitializationVector, FlagNameOmitIV, "",
			o.OmitInitializationVector, "omit the initialization vector from encrypted output")

		if cmdInfo.cmdName == "aes" {
			cryptoCmd.Flags().StringVarP(&o.AdditionalDataFilename, "additional-data", "a", "",
				fmt.Sprintf("additional data filename for %q mode", cryptoModeGCM))
		}

		rootCmd.AddCommand(cryptoCmd)
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
	key, err := readKeyFile(o.KeyFilename)
	if err != nil {
		return err
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
	key, err := readKeyFile(o.KeyFilename)
	if err != nil {
		return err
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

// readKeyFile reads the key file, returning an error instead of aborting the
// process so callers can surface it through Cobra's normal error handling.
func readKeyFile(filename string) ([]byte, error) {
	if filename == "" {
		return nil, fmt.Errorf(`missing required "--%v" flag`, FlagNameKey)
	}
	if filename == "-" {
		return nil, fmt.Errorf(`the "--%v" flag does not support "-" (stdin); provide a file path`, FlagNameKey)
	}
	key, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}
	return key, nil
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
	iv := make([]byte, c.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	if o.InitializationVectorFilename != "" {
		if o.InitializationVectorFilename == "-" {
			return fmt.Errorf(`the "--%v" flag does not support "-" (stdin); provide a file path`, FlagNameIV)
		}
		bs, err := os.ReadFile(o.InitializationVectorFilename)
		if err != nil {
			return fmt.Errorf(`failed to read "iv" file: %v`, err)
		}
		if len(bs) != c.BlockSize() {
			return fmt.Errorf("invalid initialization vector size %v for block size %v", len(bs), c.BlockSize())
		}
		iv = bs
	} else if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	stream := cipher.NewCTR(c, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	output := ciphertext
	if !o.OmitInitializationVector {
		output = append(iv, ciphertext...)
	} else if o.InitializationVectorFilename == "" {
		log.Printf("iv=%v", hex.EncodeToString(iv))
	}
	if _, err := ciphertextWriter.Write(output); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

// CTR mode encryption.
func decryptCTR(cipherName string, c cipher.Block, ciphertext []byte, plaintextWriter io.Writer, o *Options) error {
	var iv []byte
	var plaintext []byte
	offset := c.BlockSize()
	if o.InitializationVectorFilename == "" {
		iv = ciphertext[:offset]
		plaintext = ciphertext[offset:]
	} else if o.InitializationVectorFilename == "-" {
		return fmt.Errorf(`the "--%v" flag does not support "-" (stdin); provide a file path`, FlagNameIV)
	} else {
		bs, err := os.ReadFile(o.InitializationVectorFilename)
		if err != nil {
			return fmt.Errorf(`failed to read "iv" file: %v`, err)
		}
		if len(bs) != c.BlockSize() {
			return fmt.Errorf("invalid initialization vector size %v for block size %v", len(bs), c.BlockSize())
		}
		iv = bs
		plaintext = ciphertext
		offset = 0
	}
	stream := cipher.NewCTR(c, iv)
	stream.XORKeyStream(plaintext, ciphertext[offset:])
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
	if err := rejectIVFlagsForGCM(o); err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	// GCM generates a fresh nonce per encryption and always prepends it to
	// the ciphertext.
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

// TODO: support "--omit-iv" for GCM mode (stop prepending the nonce to
// ciphertext, logging it via log.Printf like CTR mode does) plus "--iv" on
// decrypt only (read the nonce back from a file). Keep "--iv" on encrypt
// rejected, since a user-supplied GCM nonce risks catastrophic reuse.

// rejectIVFlagsForGCM errors out rather than silently ignoring --iv/--omit-iv
// in GCM mode: the nonce is always random and always prepended to the
// ciphertext, so honoring either flag would be misleading.
func rejectIVFlagsForGCM(o *Options) error {
	if o.InitializationVectorFilename != "" || o.OmitInitializationVector {
		return fmt.Errorf(`the "--%v" and "--%v" flags are not supported in %q mode: a random nonce is always generated and prepended to the ciphertext`,
			FlagNameIV, FlagNameOmitIV, cryptoModeGCM)
	}
	return nil
}

func readAdditionalData(filename string) ([]byte, error) {
	if filename != "" {
		if filename == "-" {
			return nil, fmt.Errorf(`the "--additional-data" flag does not support "-" (stdin); provide a file path`)
		}
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
	if err := rejectIVFlagsForGCM(o); err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short: %v bytes, need at least %v for the nonce", len(ciphertext), nonceSize)
	}
	nonce := ciphertext[:nonceSize]
	additionalData, err := readAdditionalData(o.AdditionalDataFilename)
	if err != nil {
		return err
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
