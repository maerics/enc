package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

type StreamingCodec struct {
	Name    string
	Decoder func(io.Reader, *Options) io.Reader // TODO: options
	Encoder func(io.Writer) io.WriteCloser      // TODO: options
}

var streamingCodecs = []StreamingCodec{
	{"base32",
		func(r io.Reader, o *Options) io.Reader { return base32.NewDecoder(base32.StdEncoding, wsiro(r, o)) },
		func(w io.Writer) io.WriteCloser { return base32.NewEncoder(base32.StdEncoding, w) }},
	{"base64",
		func(r io.Reader, o *Options) io.Reader { return base64.NewDecoder(base64.StdEncoding, wsiro(r, o)) },
		func(w io.Writer) io.WriteCloser { return base64.NewEncoder(base64.StdEncoding, w) }},
	{"hex",
		func(r io.Reader, o *Options) io.Reader { return hex.NewDecoder(wsiro(r, o)) },
		func(w io.Writer) io.WriteCloser { return wnc(hex.NewEncoder(w)) }},
}

func addStreamingCodecs(rootCmd *cobra.Command, options *Options) {
	for _, codec := range streamingCodecs {
		cmd := &cobra.Command{
			Use:   codec.Name,
			Short: fmt.Sprintf("Encode %q between stdin and stdout.", codec.Name),
			Run:   transcodeStreaming(codec, os.Stdin, os.Stdout, options),
		}
		cmd.Flags().BoolVarP(&options.Decode, "decode", "D", options.Decode,
			fmt.Sprintf("decode input from %q to binary", codec.Name))
		cmd.Flags().BoolVarP(&options.IgnoreWhitespace,
			"ignore-whitespace", "w", options.IgnoreWhitespace,
			"ignore ASCII whitespace characters when decoding")
		rootCmd.AddCommand(cmd)
	}
}

func transcodeStreaming(codec StreamingCodec, in io.Reader, out io.WriteCloser, o *Options) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		if o.Decode {
			in = codec.Decoder(in, o)
		} else {
			out = codec.Encoder(out)
		}

		if _, err := io.Copy(out, in); err != nil {
			log.Fatalf("FATAL: transcoding failed: %v", err)
		}
		if err := out.Close(); err != nil {
			log.Fatalf("FATAL: failed to close output stream: %v", err)
		}
	}
}
