package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BufferedCodec struct {
	Name string

	Encode func([]byte, *Options) ([]byte, error)
	Decode func([]byte, *Options) ([]byte, error)

	SetFlags   func(*pflag.FlagSet, *Options)
	ParseFlags func(*Options) error
}

func addBufferedCodecs(rootCmd *cobra.Command, options *Options) {
	for _, codec := range bufferedCodecs {
		cmd := &cobra.Command{
			Use:   codec.Name,
			Short: fmt.Sprintf("Encode %q between stdin and stdout.", codec.Name),
			Run: func(*cobra.Command, []string) {
				if err := codec.ParseFlags(options); err != nil {
					log.Fatalf("FATAL: %v", err)
				}
				transcodeBuffered(codec, options)
			},
		}
		codec.SetFlags(cmd.Flags(), options)
		cmd.Flags().BoolVarP(&options.Decode, "decode", "D", options.Decode,
			`decode input from "base58" to binary`)
		rootCmd.AddCommand(cmd)
	}
}

var bufferedCodecs = []BufferedCodec{
	{Name: "base58",
		Encode: func(input []byte, o *Options) ([]byte, error) {
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
		Decode: func(input []byte, options *Options) ([]byte, error) {
			// First try check decoding.
			var version byte
			output, version, err := base58.CheckDecode(string(input))
			if err == nil {
				fmt.Fprintf(os.Stderr, "Version Byte: %v (0x%02x)\n", version, version)
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

func transcodeBuffered(codec BufferedCodec, options *Options) {
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("FATAL: failed to read stdin: %v", err)
	}

	var output []byte
	if options.Decode {
		output, err = codec.Decode(input, options)
	} else {
		output, err = codec.Encode(input, options)
	}
	if err != nil {
		log.Fatalf("FATAL: transcoding %q failed: %v", codec.Name, err)
	}
	if _, err := os.Stdout.Write(output); err != nil {
		log.Fatalf("FATAL: failed to write output: %v", err)
	}
	if err := os.Stdout.Close(); err != nil {
		log.Fatalf("FATAL: failed to close output stream: %v", err)
	}
}
