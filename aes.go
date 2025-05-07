package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/spf13/cobra"
)

const CipherNameAES = "AES"

func addAESCommands(rootCmd *cobra.Command, o *Options) {
	o.CryptoMode = cryptoModeGCMAEAD
	short := "Encrypt input using " + CipherNameAES
	if o.Decode {
		short = "Decrypt input using " + CipherNameAES
	}

	aesCmd := &cobra.Command{
		Use:   "aes",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cipherFunc := func(k []byte) (cipher.Block, error) { return aes.NewCipher(k) }
			if o.Decode {
				return decrypt(cmd, o, CipherNameAES, cipherFunc)
			}
			return encrypt(cmd, o, CipherNameAES, cipherFunc)
		},
	}

	aesCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")

	aesCmd.Flags().StringVarP(&o.AdditionalDataFilename, "additional-data", "a", "",
		fmt.Sprintf("additional data filename for %q mode", cryptoModeGCMAEAD))

	aesCmd.Flags().Var(&o.CryptoMode, "mode", o.EncryptionModeString()+" mode: "+cryptoModesString)

	rootCmd.AddCommand(aesCmd)
}
