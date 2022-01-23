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

type FlagOptions struct {
	CheckVersionStr string
}

func main() {
	globalOpts := &enc.Options{}
	flagOpts := &FlagOptions{}
	opts := &enc.Options{}

	// Encoding commands.
	for _, name := range []string{"hex", "base32", "base58", "base64"} {
		cmd := &cobra.Command{
			Use:   name,
			Short: fmt.Sprintf("Encode data from stdin into %v", name),
			Run:   Encode(name, globalOpts, opts, flagOpts)}
		cmd.Flags().BoolVarP(&opts.Decode, "decode", "D", false, "Decode input")
		if name == "base58" {
			cmd.Flags().StringVarP(&flagOpts.CheckVersionStr,
				"check", "", "", "Check version byte for encoding")
		}
		rootCmd.AddCommand(cmd)
	}

	// Global/main flags.
	rootCmd.Flags().BoolVarP(&globalOpts.Decode, "decode", "D", false, "Decode input")

	// Run main.
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	os.Exit(0)
}

func Encode(target string, globalOpts, opts *enc.Options, flagOpts *FlagOptions) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		// TODO: merge global options into options?

		if target == "base58" && flagOpts != nil && flagOpts.CheckVersionStr != "" {
			v, err := enc.ParseBase58CheckVersionByteInput(flagOpts.CheckVersionStr)
			if err != nil {
				log.Fatalf("FATAL: invalid check version byte: %v", err)
			}
			opts.CheckVersion = &v
		}

		if _, err := enc.Encode(target, *opts, os.Stdin, os.Stdout); err != nil {
			log.Fatalf("FATAL: %v", err)
		}
	}
}
