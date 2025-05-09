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

	for _, algo := range []desCommandInfo{
		{"des", CipherNameDES, des.NewCipher, nil},
		{"des3", CipherNameTRIPLEDES, des.NewTripleDESCipher, []string{"3des", "tripledes", "triple-des"}},
	} {
		(func(cmdInfo desCommandInfo) {
			o.CryptoMode = cryptoModeBlock
			short := "Encrypt input using " + cmdInfo.cipherName
			if o.Decode {
				short = "Decrypt input using " + cmdInfo.cipherName
			}

			desCmd := &cobra.Command{
				Use:     cmdInfo.cmdName,
				Short:   short,
				Args:    cobra.NoArgs,
				Aliases: cmdInfo.aliases,
				RunE: func(cmd *cobra.Command, _ []string) error {
					if o.Decode {
						return decrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
					}
					return encrypt(cmd, o, cmdInfo.cipherName, cmdInfo.cipherFunc)
				},
			}

			desCmd.Flags().StringVarP(&o.KeyFilename, FlagNameKey, "k", "", "key filename")
			desCmd.Flags().VarP(&o.CryptoMode, "mode", "m", o.EncryptionModeString()+" mode: "+cryptoModesString)

			rootCmd.AddCommand(desCmd)
		})(algo)
	}
}
