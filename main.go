package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type Options struct {
	Decode           bool
	IgnoreWhitespace bool
	AppendNewline    bool

	CheckVersion     *uint8
	CheckVersionFlag string

	Key    string
	Offset uint8
}

func main() {
	log.SetFlags(0)
	options := getDefaultOptions()

	rootCmd := &cobra.Command{
		Use: "enc", Short: "Transcode various formats between stdin and stdout.",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	rootCmd.Flags().BoolVarP(&options.Decode,
		"decode", "D", options.Decode,
		"decode input on stdin")
	rootCmd.Flags().BoolVarP(&options.IgnoreWhitespace,
		"ignore-whitespace", "w", options.IgnoreWhitespace,
		"ignore whitespace characters when decoding")
	rootCmd.Flags().BoolVarP(&options.AppendNewline,
		"append-newline", "n", options.AppendNewline,
		"append a trailing newline to the output")

	addStreamingCodecs(rootCmd, options)
	addBufferedCodecs(rootCmd, options)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getDefaultOptions() *Options {
	options := &Options{}
	cmdName := filepath.Base(os.Args[0])
	if cmdName == "dec" {
		options.Decode = true
	}
	return options
}
