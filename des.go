package main

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/spf13/cobra"
)

const CipherNameDES = "DES"
const CipherNameTRIPLEDES = "3DES"

func addDESCommands(rootCmd *cobra.Command, o *Options) {
	type desCommandInfo struct {
		cmdName    string
		cipherName string
		cipherFunc func([]byte) (cipher.Block, error)
		aliases    []string
	}

	for _, x := range []desCommandInfo{
		{"des", CipherNameDES, des.NewCipher, nil},
		{"des3", CipherNameTRIPLEDES, des.NewTripleDESCipher, []string{"3des", "tripledes", "triple-des"}},
	} {
		(func(c desCommandInfo) {
			o.CryptoMode = cryptoModeBlock
			short := "Encrypt input using " + c.cipherName
			if o.Decode {
				short = "Decrypt input using " + c.cipherName
			}

			desCmd := &cobra.Command{
				Use:     c.cmdName,
				Short:   short,
				Args:    cobra.NoArgs,
				Aliases: c.aliases,
				RunE: func(cmd *cobra.Command, args []string) error {
					if o.Decode {
						return decrypt(cmd, o, CipherNameDES, c.cipherFunc)
					}
					return encrypt(cmd, o, CipherNameDES, c.cipherFunc)
				},
			}

			desCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")
			desCmd.Flags().VarP(&o.CryptoMode, "mode", "m", o.EncryptionModeString()+" mode: "+cryptoModesString)

			rootCmd.AddCommand(desCmd)
		})(x)
	}
}
