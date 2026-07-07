package main

import (
	"enc/rot13"
	"enc/xor"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type StreamingCodec struct {
	Name    string
	Aliases []string
	Decoder func(io.Reader, *Options) io.Reader
	Encoder func(io.Writer, *Options) io.WriteCloser
}

var streamingCodecs = []StreamingCodec{
	{"ascii85", nil,
		func(r io.Reader, o *Options) io.Reader { return ascii85.NewDecoder(wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return ascii85.NewEncoder(w) }},
	{"base32", nil,
		func(r io.Reader, o *Options) io.Reader { return base32.NewDecoder(base32.StdEncoding, wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return base32.NewEncoder(base32.StdEncoding, w) }},
	{"base64", nil,
		func(r io.Reader, o *Options) io.Reader { return base64.NewDecoder(base64.StdEncoding, wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return base64.NewEncoder(base64.StdEncoding, w) }},
	{"hex", nil,
		func(r io.Reader, o *Options) io.Reader { return hex.NewDecoder(wsiro(r, o)) },
		func(w io.Writer, o *Options) io.WriteCloser { return wnc(hex.NewEncoder(w)) }},
	{"rot13", []string{"rot", "caesar"},
		func(r io.Reader, o *Options) io.Reader { return rot13NewDecoderO(wsiro(r, o), o) },
		func(w io.Writer, o *Options) io.WriteCloser { return wnc(rot13NewEncoderO(w, o)) }},
	{"xor", nil,
		func(r io.Reader, o *Options) io.Reader { return xorNewDecoderO(wsiro(r, o), o) },
		func(w io.Writer, o *Options) io.WriteCloser { return wnc(xorNewEncoderO(w, o)) }},
}

func addStreamingCodecs(rootCmd *cobra.Command, options *Options) {
	for _, codec := range streamingCodecs {
		cmd := &cobra.Command{
			Use:     codec.Name,
			Aliases: codec.Aliases,
			Short:   fmt.Sprintf("%v input using %v", options.ActionName, strings.ToUpper(codec.Name)),
		}

		var base64UrlEncoding bool
		padChar, noPad := "=", false

		switch codec.Name {
		case "base64":
			cmd.Flags().BoolVarP(&base64UrlEncoding, "url", "u", false, "use URL safe encoding")
			cmd.Flags().StringVar(&padChar, "pad", padChar, "padding character")
			cmd.Flags().BoolVar(&noPad, "no-pad", false, "disable padding")
		case "base32":
			cmd.Flags().StringVar(&padChar, "pad", padChar, "padding character")
			cmd.Flags().BoolVar(&noPad, "no-pad", false, "disable padding")
		case "rot13":
			cmd.Flags().Uint8VarP(&options.Offset, "offset", "r", 13, "offset for ROT13 transcoding")
		case "xor":
			cmd.Flags().StringVarP(&options.Key, "key", "k", "", "key filename for xor transcoding")
		}
		cmd.Flags().BoolVarP(&options.IgnoreWhitespace,
			"ignore-whitespace", "w", options.IgnoreWhitespace,
			"ignore whitespace characters when decoding")
		cmd.Flags().BoolVarP(&options.AppendNewline,
			"append-newline", "n", options.AppendNewline,
			"append a trailing newline to the output")

		cmd.Run = func(c *cobra.Command, s []string) {
			switch codec.Name {
			case "base64":
				pad, err := parsePad(padChar, noPad)
				if err != nil {
					log.Fatalf("FATAL: %v", err)
				}
				enc := base64.StdEncoding
				if base64UrlEncoding {
					enc = base64.URLEncoding
				}
				enc = enc.WithPadding(pad)
				codec.Decoder = func(r io.Reader, o *Options) io.Reader { return base64.NewDecoder(enc, wsiro(r, o)) }
				codec.Encoder = func(w io.Writer, o *Options) io.WriteCloser { return base64.NewEncoder(enc, w) }
			case "base32":
				pad, err := parsePad(padChar, noPad)
				if err != nil {
					log.Fatalf("FATAL: %v", err)
				}
				enc := base32.StdEncoding.WithPadding(pad)
				codec.Decoder = func(r io.Reader, o *Options) io.Reader { return base32.NewDecoder(enc, wsiro(r, o)) }
				codec.Encoder = func(w io.Writer, o *Options) io.WriteCloser { return base32.NewEncoder(enc, w) }
			}
			transcodeStreaming(c, codec, options)
		}

		rootCmd.AddCommand(cmd)
	}
}

func transcodeStreaming(c *cobra.Command, codec StreamingCodec, o *Options) {
	ins := c.InOrStdin()
	outs := wnc(c.OutOrStdout())

	var in io.Reader = ins
	var out io.WriteCloser = outs
	if o.Decode {
		in = codec.Decoder(ins, o)
	} else {
		out = codec.Encoder(outs, o)
	}

	if _, err := io.Copy(out, in); err != nil {
		log.Fatalf("FATAL: transcoding failed: %v", err)
	}
	if err := out.Close(); err != nil {
		log.Fatalf("FATAL: failed to close output stream: %v", err)
	}
	if o.AppendNewline {
		if _, err := outs.Write([]byte{'\n'}); err != nil {
			log.Fatalf("FATAL: failed to append trailing newline: %v", err)
		}
	}
}

func parsePad(padChar string, noPad bool) (rune, error) {
	if noPad {
		return base64.NoPadding, nil
	}
	rs := []rune(padChar)
	if len(rs) != 1 {
		return 0, fmt.Errorf("invalid --pad value %q: must be exactly one character", padChar)
	}
	return rs[0], nil
}

func xorNewDecoderO(r io.Reader, o *Options) io.Reader {
	if o.Key == "" {
		log.Fatalf(`FATAL: missing required flag "--key=KEY_FILENAME"`)
	}
	if o.Key == "-" {
		log.Fatalf(`FATAL: the "--key" flag does not support "-" (stdin); provide a file path`)
	}
	key, err := os.ReadFile(o.Key)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	if len(key) == 0 {
		log.Println(`WARNING: xor with empty key has no effect, try "--key=KEY_FILENAME".`)
	}
	return xor.NewDecoder([]byte(key), r)
}

func xorNewEncoderO(w io.Writer, o *Options) io.Writer {
	if o.Key == "" {
		log.Fatalf(`FATAL: missing required flag "--key=KEY_FILENAME"`)
	}
	if o.Key == "-" {
		log.Fatalf(`FATAL: the "--key" flag does not support "-" (stdin); provide a file path`)
	}
	key, err := os.ReadFile(o.Key)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	if len(key) == 0 {
		log.Println(`WARNING: xor with empty key has no effect, try "--key=...".`)
	}
	return xor.NewEncoder(key, w)
}

func rot13NewDecoderO(r io.Reader, o *Options) io.Reader {
	if o.Offset%26 == 0 {
		log.Println("WARNING: rot13 with offset%%26==0 has no effect")
	}
	return rot13.NewDecoder(o.Offset, r)
}

func rot13NewEncoderO(w io.Writer, o *Options) io.Writer {
	if o.Offset%26 == 0 {
		log.Println("WARNING: rot13 with offset%%26==0 has no effect")
	}
	return rot13.NewEncoder(o.Offset, w)
}
