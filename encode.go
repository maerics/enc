package enc

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
)

func Encode(target string, opts Options, in io.Reader, out io.WriteCloser) (int64, error) {
	switch target {
	case "hex":
		if opts.Decode {
			in = hex.NewDecoder(in)
		} else {
			out = wc(hex.NewEncoder(out))
		}
	case "base32":
		if opts.Decode {
			in = base32.NewDecoder(base32.StdEncoding, in)
		} else {
			out = base32.NewEncoder(base32.StdEncoding, out)
		}
	case "base58":
		n, err := base58Codec(opts, in, out)
		return int64(n), err
	case "base64":
		if opts.Decode {
			in = base64.NewDecoder(base64.StdEncoding, in)
		} else {
			out = base64.NewEncoder(base64.StdEncoding, out)
		}
	default:
		return 0, fmt.Errorf("unknown encoding %q", target)
	}

	// Apply the encoding
	n, err := io.Copy(out, in)
	if err != nil {
		return 0, fmt.Errorf("encoding failed: %w", err)
	}
	return n, out.Close()
}

func base58Codec(opts Options, in io.Reader, out io.WriteCloser) (int, error) {
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return 0, err
	}

	if opts.Decode {
		// First try check decoding.
		result, version, err := base58.CheckDecode(string(data))
		if err == nil {
			if opts.FormatJSON {
				return out.Write(append(mustJSON(struct {
					Version byte   `json:"version"`
					Data    string `json:"data"`
				}{version, string(result)}), '\n'))
			} else {
				fmt.Fprintf(os.Stderr, "Version Byte: 0x%02x\n", version)
				return out.Write(result)
			}
		}

		// Then try plain decoding.
		result = base58.Decode(string(data))
		if len(result) == 0 && len(data) != 0 {
			return 0, fmt.Errorf("invalid base58 input")
		}
		return out.Write(result)
	}

	if opts.CheckVersion != nil {
		return out.Write([]byte(base58.CheckEncode(data, *opts.CheckVersion)))
	}
	encoded := base58.Encode(data)
	return out.Write([]byte(encoded))
}

func ParseBase58CheckVersionByteInput(input string) (byte, error) {
	base := 10
	s := input
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, s = 16, input[2:]
	}
	n, err := strconv.ParseUint(s, base, 8)
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("out of range %q", input)
	}
	if errors.Is(err, strconv.ErrSyntax) {
		return 0, fmt.Errorf("syntax error %q", input)
	}
	if err != nil {
		return 0, err
	}
	return byte(n), nil
}

var _ io.WriteCloser = WriteCloseNooper{}

func wc(w io.Writer) WriteCloseNooper {
	return WriteCloseNooper{w}
}

type WriteCloseNooper struct {
	io.Writer
}

func (WriteCloseNooper) Close() error {
	return nil
}
