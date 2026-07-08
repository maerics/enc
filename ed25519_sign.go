package main

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func addEd25519SignCmd(ed25519Cmd *cobra.Command) {
	var privateFilename string
	var keyFilename string

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign input using an Ed25519 private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := &Options{PrivateKeyFilename: privateFilename, KeyFilename: keyFilename}
			privateKey, err := readEd25519PrivateKey(cmd, o)
			if err != nil {
				return err
			}

			message, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}

			sig := ed25519.Sign(privateKey, message)

			if _, err := cmd.OutOrStdout().Write(sig); err != nil {
				return fmt.Errorf("failed to write signature: %v", err)
			}
			return nil
		},
	}

	signCmd.Flags().StringVar(&privateFilename, FlagNamePrivateKey, "",
		"private key filename")
	signCmd.Flags().StringVarP(&keyFilename, FlagNameKey, "k", "",
		"private key filename, equivalent to --"+FlagNamePrivateKey)

	ed25519Cmd.AddCommand(signCmd)
}

func addEd25519VerifyCmd(ed25519Cmd *cobra.Command) {
	var publicFilename string
	var keyFilename string
	var signatureFilename string

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify input against a signature using an Ed25519 public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := &Options{PublicKeyFilename: publicFilename, KeyFilename: keyFilename}
			publicKey, err := readEd25519PublicKey(cmd, o)
			if err != nil {
				return err
			}

			sigReader := fileReader(cmd, "signature", signatureFilename, false)
			if sigReader == nil {
				return fmt.Errorf(`missing or invalid value for signature flag %v=%q`,
					"--"+FlagNameSignature, signatureFilename)
			}
			sig, err := io.ReadAll(sigReader)
			if err != nil {
				return fmt.Errorf("failed to read signature: %v", err)
			}

			message, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}

			if !ed25519.Verify(publicKey, message, sig) {
				return fmt.Errorf("signature verification failed")
			}

			if _, err := cmd.OutOrStdout().Write(message); err != nil {
				return fmt.Errorf("failed to write output: %v", err)
			}
			return nil
		},
	}

	verifyCmd.Flags().StringVar(&publicFilename, FlagNamePublicKey, "",
		"public key filename")
	verifyCmd.Flags().StringVarP(&keyFilename, FlagNameKey, "k", "",
		"public key filename, equivalent to --"+FlagNamePublicKey)
	verifyCmd.Flags().StringVarP(&signatureFilename, FlagNameSignature, "s", "",
		"signature filename")

	ed25519Cmd.AddCommand(verifyCmd)
}
