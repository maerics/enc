package main

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/spf13/cobra"
)

const CipherNameDES = "DES"

func addDESCommands(rootCmd *cobra.Command, o *Options) {
	o.CryptoMode = cryptoModeBlock
	short := "Encrypt input using " + CipherNameDES
	if o.Decode {
		short = "Decrypt input using " + CipherNameDES
	}

	desCmd := &cobra.Command{
		Use:   "des",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cipherFunc := func(k []byte) (cipher.Block, error) { return des.NewCipher(k) }
			if o.Decode {
				return decrypt(cmd, o, CipherNameDES, cipherFunc)
			}
			return encrypt(cmd, o, CipherNameDES, cipherFunc)
		},
	}

	desCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")

	desCmd.Flags().VarP(&o.CryptoMode, "mode", "m", o.EncryptionModeString()+" mode: "+cryptoModesString)

	rootCmd.AddCommand(desCmd)
}
