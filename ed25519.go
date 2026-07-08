package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	"github.com/spf13/cobra"
)

func addEd25519Commands(rootCmd *cobra.Command, _ *Options) {
	ed25519Cmd := &cobra.Command{
		Use:   "ed25519",
		Short: "Generate, sign, and verify using Ed25519 keys",
		Args:  cobra.NoArgs,
	}

	addEd25519GenerateCmd(ed25519Cmd)
	addEd25519ExtractPublicKeyCmd(ed25519Cmd)
	addEd25519SignCmd(ed25519Cmd)
	addEd25519VerifyCmd(ed25519Cmd)
	rootCmd.AddCommand(ed25519Cmd)
}

func addEd25519GenerateCmd(ed25519Cmd *cobra.Command) {
	var privateFilename string
	var publicFilename string

	generateCmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new Ed25519 private key pair",
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatalf("FATAL: failed to generate Ed25519 key: %v", err)
			}

			privateWriter := fileWriter(ed25519Cmd, FilenameDescriptionPrivateKey, privateFilename, true, 0400)
			publicWriter := fileWriter(ed25519Cmd, FilenameDescriptionPublicKey, publicFilename, true, 0444)

			privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				log.Fatalf("FATAL: failed to marshal private key: %v", err)
			}
			pem.Encode(privateWriter, &pem.Block{Type: PrivateKeyPEMType, Bytes: privateKeyBytes})

			publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				log.Fatalf("FATAL: failed to marshal public key: %v", err)
			}
			pem.Encode(publicWriter, &pem.Block{Type: PublicKeyPEMType, Bytes: publicKeyBytes})
		},
	}

	generateCmd.Flags().StringVar(&privateFilename, FlagNamePrivateKey, "-",
		"file from which to read or write the private key")

	generateCmd.Flags().StringVar(&publicFilename, FlagNamePublicKey, "-",
		"file from which to read or write the public key")

	ed25519Cmd.AddCommand(generateCmd)
}

func addEd25519ExtractPublicKeyCmd(ed25519Cmd *cobra.Command) {
	var privateFilename string
	var publicFilename string

	extractPublicKeyCmd := &cobra.Command{
		Use:     "extract",
		Aliases: []string{"extract-public-key", "extract-public", "epk", "ep", "e"},
		Short:   "Extract the public key from a given private key",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			privateReader := fileReader(cmd, "private", privateFilename, true)
			privateKeyBytes, err := io.ReadAll(privateReader)
			if err != nil {
				log.Fatalf("FATAL: failed to read private key bytes: %v", err)
			}
			privateKeyPEM, _ := pem.Decode(privateKeyBytes)
			if privateKeyPEM == nil {
				log.Fatalf("FATAL: failed to decode private key PEM")
			}
			parsed, err := x509.ParsePKCS8PrivateKey(privateKeyPEM.Bytes)
			if err != nil {
				log.Fatalf("FATAL: failed to parse private key: %v", err)
			}
			privateKey, ok := parsed.(ed25519.PrivateKey)
			if !ok {
				log.Fatalf("FATAL: private key is not an Ed25519 key")
			}

			publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
			if err != nil {
				log.Fatalf("FATAL: failed to marshal public key: %v", err)
			}
			publicWriter := fileWriter(ed25519Cmd, FilenameDescriptionPublicKey, publicFilename, true, 0444)
			pem.Encode(publicWriter, &pem.Block{Type: PublicKeyPEMType, Bytes: publicKeyBytes})
		},
	}

	extractPublicKeyCmd.Flags().StringVar(&privateFilename, FlagNamePrivateKey, "-",
		"file from which to read or write the private key")

	extractPublicKeyCmd.Flags().StringVar(&publicFilename, FlagNamePublicKey, "-",
		"file from which to read or write the public key")

	ed25519Cmd.AddCommand(extractPublicKeyCmd)
}

func readEd25519PrivateKey(cmd *cobra.Command, o *Options) (ed25519.PrivateKey, error) {
	filename := parseKeyFlagFrom(o, FlagNamePrivateKey, o.PrivateKeyFilename)
	reader := fileReader(cmd, FilenameDescriptionPrivateKey, filename, false)
	if reader == nil {
		return nil, fmt.Errorf(`missing or invalid value for %v flag %v=%q`,
			FilenameDescriptionPrivateKey, "--"+FlagNamePrivateKey, o.PrivateKeyFilename)
	}
	bs, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key bytes: %v", err)
	}
	block, _ := pem.Decode(bs)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an Ed25519 key")
	}
	return privateKey, nil
}

func readEd25519PublicKey(cmd *cobra.Command, o *Options) (ed25519.PublicKey, error) {
	filename := parseKeyFlagFrom(o, FlagNamePublicKey, o.PublicKeyFilename)
	reader := fileReader(cmd, FilenameDescriptionPublicKey, filename, false)
	if reader == nil {
		return nil, fmt.Errorf(`missing or invalid value for %v flag %v=%q`,
			FilenameDescriptionPublicKey, "--"+FlagNamePublicKey, o.PublicKeyFilename)
	}
	bs, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key bytes: %v", err)
	}
	block, _ := pem.Decode(bs)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an Ed25519 key")
	}
	return publicKey, nil
}
