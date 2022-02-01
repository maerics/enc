package xor

import "io"

func NewDecoder(key []byte, r io.Reader) io.Reader {
	return &codec{key: key, r: r}
}

func NewEncoder(key []byte, w io.Writer) io.Writer {
	return &codec{key: key, w: w}
}

type codec struct {
	key []byte
	r   io.Reader
	w   io.Writer
}

func (c *codec) xor(bs []byte) []byte {
	k, n := c.key, len(c.key)
	if n > 0 {
		for i := range bs {
			bs[i] ^= k[i%n]
		}
	}
	return bs
}

func (c *codec) Read(bs []byte) (int, error) {
	n, err := c.r.Read(bs)
	if err == nil {
		c.xor(bs)
	}
	return n, err
}

func (c *codec) Write(bs []byte) (int, error) {
	return c.w.Write(c.xor(bs))
}
