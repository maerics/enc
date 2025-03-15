package main

import (
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
)

type Options struct {
	CmdName string
	ActName string

	Decode           bool
	IgnoreWhitespace bool
	AppendNewline    bool

	CheckVersion     *uint8
	CheckVersionFlag string

	Key    string
	Offset uint8

	InputFilename  string
	OutputFilename string
}

func newEncCmd(options *Options) *cobra.Command {
	return &cobra.Command{
		Use: options.CmdName, Short: "Transcode various formats between streams or files.",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
}

var encCmd = newEncCmd(getDefaultOptions())

func main() {
	log.SetFlags(0)
	options := getDefaultOptions()

	// Setup global flags.
	encCmd.PersistentFlags().BoolVarP(&options.Decode,
		"decode", "D", options.Decode,
		"decode input on stdin")
	encCmd.PersistentFlags().BoolVarP(&options.IgnoreWhitespace,
		"ignore-whitespace", "w", options.IgnoreWhitespace,
		"ignore whitespace characters when decoding")
	encCmd.PersistentFlags().BoolVarP(&options.AppendNewline,
		"append-newline", "n", options.AppendNewline,
		"append a trailing newline to the output")
	encCmd.PersistentFlags().StringVarP(&options.InputFilename,
		"input-file", "i", options.InputFilename,
		"the input filename, omit or use \"-\" for stdin")
	encCmd.PersistentFlags().StringVarP(&options.OutputFilename,
		"output-file", "o", options.OutputFilename,
		"the output filename, omit or use \"-\" for stdout")

	encCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		setFilenameOptions(cmd, options)
	}

	// Add the subcommands
	addStreamingCodecs(encCmd, options)
	addBufferedCodecs(encCmd, options)
	addRSACommands(encCmd, options)

	// Execute the "enc/dec" cmd.
	if err := encCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getDefaultOptions() *Options {
	// Determine if we're being called as "dec" instead of "enc".
	options := &Options{CmdName: EncodeCmdName, ActName: EncodeActName}
	cmdName := filepath.Base(os.Args[0])
	if cmdName == DecodeCmdName {
		options.Decode = true
		options.CmdName = DecodeCmdName
		options.ActName = DecodeActName
	}
	return options
}

func setFilenameOptions(cmd *cobra.Command, options *Options) {
	infilename := options.InputFilename
	if infilename != "" && infilename != DefaultStreamName {
		if in, err := os.Open(infilename); err != nil {
			log.Fatalf("FATAL: failed to open input file %q for reading: %v", infilename, err)
		} else {
			cmd.SetIn(in)
		}
	}

	outfilename := options.OutputFilename
	if outfilename != "" && outfilename != DefaultStreamName {
		flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if out, err := os.OpenFile(outfilename, flag, 0600); err != nil {
			log.Fatalf("FATAL: failed to open output file %q for writing: %v", outfilename, err)
		} else {
			cmd.SetOut(out)
		}
	}
}
