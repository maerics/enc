package main

import (
	"enc"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

// enc code {hex,base32,base58,base64} [-D]
// enc crypt {-aes,-ed25519,-rsa} [-D] --key=x
// enc dgst -{md5,sha1,sha256,sha384,sha512}
// enc hash [-base64,-hex*,-sri] [--json]
// enc pass {bcrypt,scrypt}
var rootCmd = &cobra.Command{
	Use:   "enc",
	Short: "Encode, encrypt, and digest data on stdin.",
}

var decode bool

func main() {
	// Encoding commands.
	for _, enc := range []string{"hex", "base32", "base58", "base64"} {
		cmd := &cobra.Command{
			Use:   enc,
			Short: fmt.Sprintf("Encode data from stdin into %v", enc),
			Run:   Encode(enc)}
		cmd.Flags().BoolVarP(&decode, "decode", "D", false, "Decode input")
		rootCmd.AddCommand(cmd)
	}

	// Global/main flags.
	rootCmd.Flags().BoolVarP(&decode, "decode", "D", false, "Decode input")

	// Run main.
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	os.Exit(0)
}

func Encode(target string) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		out := os.Stdout
		_, err := enc.Encode(target, decode, os.Stdin, out)
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}
	}
}
