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

	// Compact non-whitespace bytes in place, single pass over bs[:n].
	out := 0
	for i := 0; i < n; i++ {
		if !unicode.IsSpace(rune(bs[i])) {
			bs[out] = bs[i]
			out++
		}
	}
	return out, err
}

func wsiro(r io.Reader, o *Options) io.Reader {
	if o.IgnoreWhitespace {
		return WhitespaceIgnoringReader{r}
	}
	return r
}
