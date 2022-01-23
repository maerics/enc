package enc

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

func Encode(target string, decode bool, in io.Reader, out io.WriteCloser) (int64, error) {
	switch target {
	case "hex":
		if decode {
			in = hex.NewDecoder(in)
		} else {
			out = wc(hex.NewEncoder(out))
		}
	case "base32":
		if decode {
			in = base32.NewDecoder(base32.StdEncoding, in)
		} else {
			out = base32.NewEncoder(base32.StdEncoding, out)
		}
	case "base64":
		if decode {
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

func wc(w io.Writer) WriteCloseNooper {
	return WriteCloseNooper{w}
}

type WriteCloseNooper struct {
	io.Writer
}

func (WriteCloseNooper) Close() error {
	return nil
}
