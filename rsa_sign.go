package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

const (
	FlagNameHash      = "hash"
	FlagNameSignature = "signature"
)

var rsaHashAlgorithms = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

var rsaHashNames = []string{"sha256", "sha384", "sha512"}

func addSignCmd(rsaCmd *cobra.Command) {
	var privateFilename string
	var keyFilename string
	var hashName string

	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign input using an RSA private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hash, ok := rsaHashAlgorithms[hashName]
			if !ok {
				return fmt.Errorf("invalid %q flag %q: must be one of %v",
					"--"+FlagNameHash, hashName, strings.Join(rsaHashNames, ", "))
			}

			o := &Options{PrivateKeyFilename: privateFilename, KeyFilename: keyFilename}
			privateKey, err := readRSAPrivateKey(cmd, o)
			if err != nil {
				return err
			}

			message, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}

			h := hash.New()
			h.Write(message)
			sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
			if err != nil {
				return fmt.Errorf("failed to sign input: %v", err)
			}

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
	signCmd.Flags().StringVarP(&hashName, FlagNameHash, "a", "sha256",
		"hash algorithm: "+strings.Join(rsaHashNames, ", "))

	rsaCmd.AddCommand(signCmd)
}

func addVerifyCmd(rsaCmd *cobra.Command) {
	var publicFilename string
	var keyFilename string
	var hashName string
	var signatureFilename string

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify input against a signature using an RSA public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hash, ok := rsaHashAlgorithms[hashName]
			if !ok {
				return fmt.Errorf("invalid %q flag %q: must be one of %v",
					"--"+FlagNameHash, hashName, strings.Join(rsaHashNames, ", "))
			}

			o := &Options{PublicKeyFilename: publicFilename, KeyFilename: keyFilename}
			publicKey, err := readRSAPublicKey(cmd, o)
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

			h := hash.New()
			h.Write(message)
			if err := rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), sig); err != nil {
				return fmt.Errorf("signature verification failed: %v", err)
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
	verifyCmd.Flags().StringVarP(&hashName, FlagNameHash, "a", "sha256",
		"hash algorithm: "+strings.Join(rsaHashNames, ", "))
	verifyCmd.Flags().StringVarP(&signatureFilename, FlagNameSignature, "s", "",
		"signature filename")

	rsaCmd.AddCommand(verifyCmd)
}
