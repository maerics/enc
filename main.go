package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const (
	EncodeCmdName = "enc"
	EncodeActName = "Encode"

	DecodeCmdName = "dec"
	DecodeActName = "Decode"

	DefaultStreamName = "-"

	FilenameDescriptionPrivateKey = "private key"
	FilenameDescriptionPublicKey  = "public key"
	FilenameDescriptionCipherText = "cipher text"
	FilenameDescriptionPlainText  = "plain text"

	FlagNamePrivateKey = "private-key"
	FlagNamePublicKey  = "public-key"
	FlagNameKey        = "key"
	FlagNameIV         = "iv"
	FlagNameOmitIV     = "omit-iv"
)

type Options struct {
	CmdName    string
	ActionName string

	Decode           bool
	IgnoreWhitespace bool
	AppendNewline    bool

	CheckVersion     *uint8
	CheckVersionFlag string

	Key      string
	KeyBytes []byte
	Offset   uint8

	InputFilename  string
	OutputFilename string

	PrivateKeyFilename string
	PublicKeyFilename  string
	KeyFilename        string

	AdditionalDataFilename       string
	InitializationVectorFilename string
	OmitInitializationVector     bool

	CryptoMode cryptoMode
}

func (o *Options) EncryptionModeString() string {
	if o.Decode {
		return "decryption"
	}
	return "encryption"
}

// Linked at build time.
var version, commit, date, modified string

func newEncCmd(options *Options) *cobra.Command {
	printVersion := false
	description := "Encrypt and encode between streams and files."
	if options.Decode {
		description = "Decrypt and decode between streams and files."
	}

	encCmd := &cobra.Command{
		Use:               options.CmdName,
		Short:             description,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	versionCmd := &cobra.Command{
		Use:               "version",
		Aliases:           []string{"v"},
		Short:             "Print the current version",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			bs, err := json.MarshalIndent(parseVersionInfo(), "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(bs))
			return nil
		},
	}

	encCmd.AddCommand(versionCmd)
	encCmd.Flags().BoolVarP(&printVersion, "version", "v", false, "print the current version")

	// Setup global flags.
	encCmd.PersistentFlags().BoolVarP(&options.Decode,
		"decrypt", "D", options.Decode,
		"decrypt or decode input")
	encCmd.PersistentFlags().BoolVarP(&options.Decode,
		"decode", "d", options.Decode,
		"decode or decrypt input")
	encCmd.PersistentFlags().StringVarP(&options.InputFilename,
		"input-file", "i", options.InputFilename,
		"the input filename, omit or use \"-\" for stdin")
	encCmd.PersistentFlags().StringVarP(&options.OutputFilename,
		"output-file", "o", options.OutputFilename,
		"the output filename, omit or use \"-\" for stdout")

	encCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return setFilenameOptions(cmd, options)
	}

	// Add the subcommands
	addStreamingCodecs(encCmd, options)
	addBufferedCodecs(encCmd, options)
	addSymmetricCryptoCommands(encCmd, options)
	addRSACommands(encCmd, options)

	encCmd.Run = func(cmd *cobra.Command, args []string) {
		if printVersion {
			fmt.Println(getVersionString())
		} else {
			encCmd.Help()
		}
	}

	return encCmd
}

func main() {
	log.SetFlags(0)
	if err := newEncCmd(getDefaultOptions()).Execute(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

func getDefaultOptions() *Options {
	// Determine if we're being called as "dec" instead of "enc".
	options := &Options{CmdName: EncodeCmdName, ActionName: EncodeActName}
	cmdName := filepath.Base(os.Args[0])
	if cmdName == DecodeCmdName {
		options.Decode = true
		options.CmdName = DecodeCmdName
		options.ActionName = DecodeActName
	}
	return options
}

func setFilenameOptions(cmd *cobra.Command, options *Options) error {
	infilename := options.InputFilename
	if infilename != "" && infilename != DefaultStreamName {
		if in, err := os.Open(infilename); err != nil {
			return fmt.Errorf("failed to open input file %q for reading: %v", infilename, err)
		} else {
			cmd.SetIn(in)
		}
	}

	outfilename := options.OutputFilename
	if outfilename != "" && outfilename != DefaultStreamName {
		flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if out, err := os.OpenFile(outfilename, flag, 0600); err != nil {
			return fmt.Errorf("failed to open output file %q for writing: %v", outfilename, err)
		} else {
			cmd.SetOut(out)
		}
	}
	return nil
}

type versionInfo struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Modified  string `json:"modified,omitempty"`
}

func parseVersionInfo() versionInfo {
	return versionInfo{
		Version:   version,
		Commit:    commit,
		Timestamp: date,
		Modified:  modified,
	}
}

func getVersionString() string {
	versionInfo := parseVersionInfo()

	if versionInfo.Version == "" {
		return "(unknown)"
	}

	return fmt.Sprintf("v%v, commit=%v, timestamp=%v",
		versionInfo.Version, versionInfo.Commit, versionInfo.Timestamp)
}
