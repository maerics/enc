package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const (
	RsaPrivateKeyPEMType = "RSA PRIVATE KEY"
	RsaPublicKeyPEMType  = "RSA PUBLIC KEY"
)

func addRSACommands(rootCmd *cobra.Command, options *Options) {
	keySizeBits := 2048
	var privateFilename string
	var publicFilename string
	// var format string

	rsaCmd := &cobra.Command{Use: "rsa"}

	generateCmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new RSA private key pair",
		Run: func(cmd *cobra.Command, args []string) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySizeBits)
			if err != nil {
				log.Fatalf("FATAL: failed to generate RSA key pair of %v bits: %v", err, 2048)
			}

			privateWriter := fileWriter("private", privateFilename)
			publicWriter := fileWriter("public", publicFilename)

			// Output the private key.
			privateKeyPEM := &pem.Block{
				Type:  RsaPrivateKeyPEMType,
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			}
			pem.Encode(privateWriter, privateKeyPEM)

			// Output the public key.
			publicKeyPEM := &pem.Block{
				Type:  RsaPublicKeyPEMType,
				Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			}
			pem.Encode(publicWriter, publicKeyPEM)
		},
	}

	generateCmd.Flags().StringVar(&privateFilename, "private-filename", "-",
		"file from which to read or write the private key")
	generateCmd.Flags().StringVar(&publicFilename, "public-filename", "-",
		"file from which to read or write the public key")

	rsaCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(rsaCmd)
}

func fileReader(description, filename string) io.Writer {
	if filename == "" || filename == "-" {
		return os.Stdin
	}
	w, err := os.Open(filename)
	if err != nil {
		log.Fatalf("FATAL: failed to open %v key file for reading: %v", description, err)
	}
	return w
}

func fileWriter(description, filename string) io.Writer {
	if filename == "" || filename == "-" {
		return os.Stdout
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	w, err := os.OpenFile(filename, flags, os.FileMode(0600))
	if err != nil {
		log.Fatalf("FATAL: failed to open %v key file for writing: %v", description, err)
	}
	return w
}
