package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const (
	RsaPrivateKeyPEMType       = "RSA PRIVATE KEY"
	RsaPublicKeyPEMType        = "RSA PUBLIC KEY"
	PrivateKeyPEMType          = "PRIVATE KEY"
	PublicKeyPEMType           = "PUBLIC KEY"
	EncryptedPrivateKeyPEMType = "ENCRYPTED PRIVATE KEY"
)

var (
	KeyEncodings             = []string{"der", "pem"}
	PrivateKeyFormatHeadings = map[string]string{
		"pkcs1":  RsaPrivateKeyPEMType,
		"pkcs8":  PrivateKeyPEMType,
		"pkcs12": EncryptedPrivateKeyPEMType,
	}
)

func addRSACommands(rootCmd *cobra.Command, o *Options) {
	short := "Encrypt input using RSA public key"
	if o.Decode {
		short = "Decrypt input using RSA private key"
	}

	rsaCmd := &cobra.Command{
		Use:   "rsa",
		Short: short,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if o.Decode {
				rsaDecrypt(cmd, o)
				return
			}
			rsaEncrypt(cmd, o)
		},
	}

	rsaCmd.Flags().StringVarP(&o.PrivateKeyFilename, FlagNamePrivateKey, "", "",
		FilenameDescriptionPrivateKey+" filename")
	rsaCmd.Flags().StringVarP(&o.PublicKeyFilename, FlagNamePublicKey, "", "",
		FilenameDescriptionPublicKey+" filename")
	rsaCmd.Flags().StringVarP(&o.KeyFilename, "key", "k", "",
		"public or private key filename, depending on context")

	addGenerateCmd(rsaCmd)
	addExtractPublicKeyCmd(rsaCmd)
	rootCmd.AddCommand(rsaCmd)
}

func rsaDecrypt(cmd *cobra.Command, o *Options) {
	// Warn the user if the public key argument was provided.
	if o.PublicKeyFilename != "" {
		log.Printf("WARNING: ignoring irrelevant %q flag", "--"+FlagNamePublicKey)
	}

	// Read and parse the private key.
	privateKeyFilename := parseKeyFlagFrom(o, FlagNamePrivateKey, o.PrivateKeyFilename)
	privateReader := fileReader(cmd, FilenameDescriptionPrivateKey, privateKeyFilename, false)
	if privateReader == nil {
		log.Fatalf("FATAL: missing or invalid value for %v flag %v=%q",
			FilenameDescriptionPrivateKey, "--"+FlagNamePrivateKey, o.PrivateKeyFilename)
	}
	privateKeyBytes, err := io.ReadAll(privateReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read private key bytes: %v", err)
	}
	privateKeyPEM, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		log.Fatalf("FATAL: failed to parse private key: %v", err)
	}

	// Encrypt the data.
	ciphertextReader := cmd.InOrStdin()
	ciphertext, err := io.ReadAll(ciphertextReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read ciphertext from stdin: %v", err)
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, ciphertext, nil)
	if err != nil {
		log.Fatalf("FATAL: failed to decrypt: %v", err)
	}

	// Write the plaintext.
	plaintextFile := cmd.OutOrStdout()
	plaintextFile.Write(plaintext)
}

func rsaEncrypt(cmd *cobra.Command, o *Options) {
	// Warn the user if the private key argument was provided.
	if o.PrivateKeyFilename != "" {
		log.Printf("WARNING: ignoring irrelevant %q flag", "--"+FlagNamePrivateKey)
	}

	// Read and parse the public key.
	publicKeyFilename := parseKeyFlagFrom(o, FlagNamePublicKey, o.PublicKeyFilename)
	publicReader := fileReader(cmd, FilenameDescriptionPublicKey, publicKeyFilename, false)
	if publicReader == nil {
		log.Fatalf("FATAL: missing or invalid value for %v flag %v=%q",
			FilenameDescriptionPublicKey, "--"+FlagNamePublicKey, o.PublicKeyFilename)
	}
	if publicReader == nil {
		log.Fatalf("FATAL: missing or invalid value for %v flag %v=%q",
			FilenameDescriptionPublicKey, "--"+FlagNamePublicKey, o.PublicKeyFilename)
	}

	publicKeyBytes, err := io.ReadAll(publicReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read public key bytes: %v", err)
	}
	publicKeyPEM, _ := pem.Decode(publicKeyBytes)
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyPEM.Bytes)
	if err != nil {
		log.Fatalf("FATAL: failed to parse public key: %v", err)
	}

	// Encrypt the data.
	plaintextReader := cmd.InOrStdin()
	plaintext, err := io.ReadAll(plaintextReader)
	if err != nil {
		log.Fatalf("FATAL: failed to read plaintext from stdin: %v", err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		log.Fatalf("FATAL: failed to encrypt: %v", err)
	}

	// Write the ciphertext.
	ciphertextFile := cmd.OutOrStdout()
	ciphertextFile.Write(ciphertext)
}

func parseKeyFlagFrom(o *Options, flagName, flagValue string) string {
	keyFilename := o.KeyFilename
	if keyFilename == "" {
		keyFilename = flagValue
	}
	gotBoth := o.KeyFilename != "" && flagValue != ""
	bothDiffer := o.KeyFilename != flagValue
	if gotBoth && bothDiffer {
		log.Fatalf(`FATAL: conflicting values for "--%v=%v" and "--%v=%v"; omit "--%v" flag.`,
			flagName, flagValue, FlagNameKey, o.KeyFilename, FlagNameKey)
	}
	return keyFilename
}

func addGenerateCmd(rsaCmd *cobra.Command) {
	var keySizeBits uint32 = 2048
	var privateFilename string
	var publicFilename string

	generateCmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new RSA private key pair",
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			privateKey, err := rsa.GenerateKey(rand.Reader, int(keySizeBits))
			if err != nil {
				log.Fatalf("FATAL: failed to generate RSA key pair of %v bits: %v", err, 2048)
			}

			privateWriter := fileWriter(rsaCmd, FilenameDescriptionPrivateKey, privateFilename, true, 0400)
			publicWriter := fileWriter(rsaCmd, FilenameDescriptionPublicKey, publicFilename, true, 0444)

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

	generateCmd.Flags().Uint32VarP(&keySizeBits, "key-size", "s", uint32(keySizeBits),
		"key size in bits")

	generateCmd.Flags().StringVar(&privateFilename, "private-key", "-",
		"file from which to read or write the private key")

	generateCmd.Flags().StringVar(&publicFilename, "public-key", "-",
		"file from which to read or write the public key")

	rsaCmd.AddCommand(generateCmd)
}

func addExtractPublicKeyCmd(rsaCmd *cobra.Command) {
	var privateFilename string
	var publicFilename string

	extractPublicKeyCmd := &cobra.Command{
		Use:     "extract",
		Aliases: []string{"extract-public-key", "extract-public", "epk", "ep", "e"},
		Short:   "Extract the public key from a given private key",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			// Read and parse the private key.
			privateReader := fileReader(cmd, "private", privateFilename, true)
			privateKeyBytes, err := io.ReadAll(privateReader)
			if err != nil {
				log.Fatalf("FATAL: failed to read private key bytes: %v", err)
			}
			privateKeyPEM, _ := pem.Decode(privateKeyBytes)
			privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
			if err != nil {
				log.Fatalf("FATAL: failed to parse private key: %v", err)
			}

			// Output the public key.
			publicKeyPEM := &pem.Block{
				Type:  RsaPublicKeyPEMType,
				Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			}
			publicWriter := fileWriter(rsaCmd, FilenameDescriptionPublicKey, publicFilename, true, 0444)
			pem.Encode(publicWriter, publicKeyPEM)
		},
	}

	extractPublicKeyCmd.Flags().StringVar(&privateFilename, "private-key", "-",
		"file from which to read or write the private key")

	extractPublicKeyCmd.Flags().StringVar(&publicFilename, "public-key", "-",
		"file from which to read or write the public key")

	rsaCmd.AddCommand(extractPublicKeyCmd)
}

func fileReader(cmd *cobra.Command, description, filename string, canUseStdin bool) io.Reader {
	if isStd(filename) {
		if canUseStdin {
			return cmd.InOrStdin()
		}
		return nil
	}
	w, err := os.Open(filename)
	if err != nil {
		log.Fatalf("FATAL: failed to open %v file for reading: %v", description, err)
	}
	return w
}

func fileWriter(cmd *cobra.Command, description, filename string, canUseStdout bool, mode os.FileMode) io.Writer {
	if mode == 0 {
		mode = os.FileMode(0400)
	}
	if isStd(filename) {
		if canUseStdout {
			return cmd.OutOrStdout()
		}
		return nil
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	w, err := os.OpenFile(filename, flags, mode)
	if err != nil {
		log.Fatalf("FATAL: failed to open %v file for writing: %v", description, err)
	}
	return w
}

func isStd(s string) bool {
	return s == "" || s == "-"
}
