package main

import (
	"io"
	"unicode"
)

// Wraps an io.Writer with a noop "Close" method.
type WriteNoopCloser struct{ io.Writer }

func (WriteNoopCloser) Close() error { return nil }

func wnc(w io.Writer) io.WriteCloser { return WriteNoopCloser{w} }

// Reader that ignores whitespace.
type WhitespaceIgnoringReader struct{ io.Reader }

func (w WhitespaceIgnoringReader) Read(bs []byte) (int, error) {
	n, err := w.Reader.Read(bs)
	if err != nil {
		return n, err
	}

	// Remove whitespace characters.
	// TODO: optimize runs of >1 ws.
	skip := 0
	for i := 0; i < len(bs); {
		if unicode.IsSpace(rune(bs[i])) {
			skip++
			for j := i + 1; j < len(bs); j++ {
				bs[j-1] = bs[j]
			}
		} else {
			i++
		}
	}
	return n - skip, nil
}

func wsiro(r io.Reader, o *Options) io.Reader {
	if o.IgnoreWhitespace {
		return WhitespaceIgnoringReader{r}
	}
	return r
}
