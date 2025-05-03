package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BufferedCodec struct {
	Name string

	Encode func([]byte, io.Writer, *Options) ([]byte, error)
	Decode func([]byte, io.Writer, *Options) ([]byte, error)

	SetFlags   func(*pflag.FlagSet, *Options)
	ParseFlags func(*Options) error
}

func addBufferedCodecs(rootCmd *cobra.Command, options *Options) {
	for _, codec := range bufferedCodecs {
		cmd := &cobra.Command{
			Use:   codec.Name,
			Short: fmt.Sprintf("%v input using %q", options.ActName, codec.Name),
		}
		cmd.Run = func(*cobra.Command, []string) {
			if err := codec.ParseFlags(options); err != nil {
				log.Fatalf("FATAL: %v", err)
			}
			transcodeBuffered(cmd, codec, options)
		}
		flags := cmd.Flags()
		codec.SetFlags(flags, options)
		flags.BoolVarP(&options.Decode, "decode", "D", options.Decode,
			`decode input from "base58" to binary`)
		flags.BoolVarP(&options.IgnoreWhitespace,
			"ignore-whitespace", "w", options.IgnoreWhitespace,
			"ignore whitespace characters when decoding")
		flags.BoolVarP(&options.AppendNewline,
			"append-newline", "n", options.AppendNewline,
			"append a trailing newline to the output")
		rootCmd.AddCommand(cmd)
	}
}

var bufferedCodecs = []BufferedCodec{
	{Name: "base58",
		Encode: func(input []byte, stderr io.Writer, o *Options) ([]byte, error) {
			var output []byte
			if o.CheckVersion != nil {
				output = []byte(base58.CheckEncode(input, *o.CheckVersion))
			} else {
				output = []byte(base58.Encode(input))
			}
			if len(output) == 0 && len(input) != 0 {
				return nil, fmt.Errorf("invalid base58 input")
			}
			return output, nil
		},
		Decode: func(input []byte, stderr io.Writer, options *Options) ([]byte, error) {
			// First try check decoding.
			var version byte
			output, version, err := base58.CheckDecode(string(input))
			if err == nil {
				fmt.Fprintf(stderr, "Version Byte: %v (0x%02x)\n", version, version)
				return output, nil
			}

			// Try plain decoding.
			output = base58.Decode(string(input))
			if len(output) == 0 && len(input) != 0 {
				return nil, fmt.Errorf("invalid base58 input")
			}
			return output, nil
		},
		SetFlags: func(fs *pflag.FlagSet, options *Options) {
			fs.StringVar(&options.CheckVersionFlag, "check", options.CheckVersionFlag,
				"version byte [0-255] in decimal or hex")
		},
		ParseFlags: func(options *Options) error {
			base, s := 10, strings.TrimSpace(options.CheckVersionFlag)
			if s != "" {
				if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
					base = 16
					s = s[2:]
				}
				if x, err := strconv.ParseUint(s, base, 8); errors.Is(err, strconv.ErrSyntax) {
					return fmt.Errorf("invalid check version byte syntax %q (range [0,255])", options.CheckVersionFlag)
				} else if errors.Is(err, strconv.ErrRange) {
					return fmt.Errorf("version byte %q out of range [0,255]", options.CheckVersionFlag)
				} else if err != nil {
					return fmt.Errorf("invalid check version byte %q: %v", options.CheckVersionFlag, err)
				} else {
					versionByte := uint8(x)
					options.CheckVersion = &versionByte
				}
			}
			return nil
		},
	},
}

func transcodeBuffered(c *cobra.Command, codec BufferedCodec, options *Options) {
	stdin := c.InOrStdin()
	stdout := wnc(c.OutOrStdout())
	stderr := wnc(c.OutOrStderr())
	input, err := io.ReadAll(stdin)
	if err != nil {
		log.Fatalf("FATAL: failed to read stdin: %v", err)
	}
	if options.IgnoreWhitespace {
		input = regexp.MustCompile(`\s`).ReplaceAll(input, nil)
	}

	var output []byte
	if options.Decode {
		output, err = codec.Decode(input, stderr, options)
	} else {
		output, err = codec.Encode(input, stderr, options)
	}
	if err != nil {
		log.Fatalf("FATAL: transcoding %q failed: %v", codec.Name, err)
	}
	if options.AppendNewline {
		output = append(output, '\n')
	}
	if _, err := stdout.Write(output); err != nil {
		log.Fatalf("FATAL: failed to write output: %v", err)
	}
	if err := stdout.Close(); err != nil {
		log.Fatalf("FATAL: failed to close output stream: %v", err)
	}
}
