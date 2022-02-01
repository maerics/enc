package main

import (
	"enc/xor"
	"encoding/ascii85"
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
	Decoder func(io.Reader, *Options) io.Reader
	Encoder func(io.Writer, *Options) io.WriteCloser
}

var streamingCodecs = []StreamingCodec{
	{"ascii85",
		func(r io.Reader, o *Options) io.Reader { return ascii85.NewDecoder(wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return ascii85.NewEncoder(w) }},
	{"base32",
		func(r io.Reader, o *Options) io.Reader { return base32.NewDecoder(base32.StdEncoding, wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return base32.NewEncoder(base32.StdEncoding, w) }},
	{"base64",
		func(r io.Reader, o *Options) io.Reader { return base64.NewDecoder(base64.StdEncoding, wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return base64.NewEncoder(base64.StdEncoding, w) }},
	{"hex",
		func(r io.Reader, o *Options) io.Reader { return hex.NewDecoder(wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return wnc(hex.NewEncoder(w)) }},
	{"xor",
		func(r io.Reader, o *Options) io.Reader { return xorNewDecoderO(wsiro(r, o), o) },
		func(w io.Writer, o *Options) io.WriteCloser { return wnc(xorNewEncoderO(w, o)) }},
}

func addStreamingCodecs(rootCmd *cobra.Command, options *Options) {
	for _, codec := range streamingCodecs {
		cmd := &cobra.Command{
			Use:   codec.Name,
			Short: fmt.Sprintf("Encode %q between stdin and stdout.", codec.Name),
			Run:   transcodeStreaming(codec, os.Stdin, os.Stdout, options),
		}
		if codec.Name == "xor" {
			cmd.Flags().StringVarP(&options.Key, "key", "k", "", "key for xor transcoding")
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
			out = codec.Encoder(out, o)
		}

		if _, err := io.Copy(out, in); err != nil {
			log.Fatalf("FATAL: transcoding failed: %v", err)
		}
		if err := out.Close(); err != nil {
			log.Fatalf("FATAL: failed to close output stream: %v", err)
		}
	}
}

func xorNewDecoderO(r io.Reader, o *Options) io.Reader {
	if o.Key == "" {
		log.Fatalf(`FATAL: xor with empty key has no effect, use "--key=...".`)
	}
	return xor.NewDecoder([]byte(o.Key), r)
}

func xorNewEncoderO(w io.Writer, o *Options) io.Writer {
	if o.Key == "" {
		log.Fatalf(`FATAL: xor with empty key has no effect, use "--key=...".`)
	}
	return xor.NewEncoder([]byte(o.Key), w)
}
