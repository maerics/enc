package xor

import (
	"fmt"
	"io"
)

func NewDecoder(key []byte, r io.Reader, strict bool) io.Reader {
	return &codec{key: key, r: r, strict: strict}
}

func NewEncoder(key []byte, w io.Writer, strict bool) io.Writer {
	return &codec{key: key, w: w, strict: strict}
}

type codec struct {
	key    []byte
	strict bool
	offset int
	r      io.Reader
	w      io.Writer
}

func (c *codec) xor(bs []byte) ([]byte, error) {
	k, n := c.key, len(c.key)
	if n == 0 {
		return bs, nil
	}
	for i := range bs {
		if c.strict && c.offset >= n {
			return nil, fmt.Errorf("xor: key exhausted after %v byte(s) (key is %v byte(s) long); refusing to reuse key bytes in strict mode", c.offset, n)
		}
		bs[i] ^= k[c.offset%n]
		c.offset++
	}
	return bs, nil
}

func (c *codec) Read(bs []byte) (int, error) {
	n, err := c.r.Read(bs)
	if n > 0 {
		if _, xerr := c.xor(bs[:n]); xerr != nil {
			return n, xerr
		}
	}
	return n, err
}

func (c *codec) Write(bs []byte) (int, error) {
	out, err := c.xor(bs)
	if err != nil {
		return 0, err
	}
	return c.w.Write(out)
}
