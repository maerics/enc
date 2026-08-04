// Package binary implements a streaming codec that encodes bytes as
// sequences of ASCII '0'/'1' characters (MSB first) and decodes them back.
package binary

import (
	"fmt"
	"io"
)

// OctetsPerLine is the number of octets per line in pretty-printed output,
// matching the convention of "xxd -b".
const OctetsPerLine = 6

type encoder struct {
	w      io.Writer
	pretty bool
	count  int // octets written so far, for pretty line-wrapping
}

// NewEncoder returns an encoder writing ASCII '0'/'1' octets to w. When
// pretty is true, octets are space-separated and wrapped to a newline every
// OctetsPerLine octets, like "xxd -b".
func NewEncoder(w io.Writer, pretty bool) io.WriteCloser {
	return &encoder{w: w, pretty: pretty}
}

func (e *encoder) Write(bs []byte) (int, error) {
	out := make([]byte, 0, len(bs)*9)
	for _, b := range bs {
		if e.pretty && e.count > 0 {
			if e.count%OctetsPerLine == 0 {
				out = append(out, '\n')
			} else {
				out = append(out, ' ')
			}
		}
		for bit := 0; bit < 8; bit++ {
			c := byte('0')
			if b&(1<<(7-bit)) != 0 {
				c = '1'
			}
			out = append(out, c)
		}
		e.count++
	}
	if _, err := e.w.Write(out); err != nil {
		return 0, err
	}
	return len(bs), nil
}

func (e *encoder) Close() error {
	if e.pretty && e.count > 0 {
		if _, err := e.w.Write([]byte{'\n'}); err != nil {
			return err
		}
	}
	return nil
}

type decoder struct {
	r     io.Reader
	buf   [4096]byte
	cur   byte
	nbits int
	err   error
}

func NewDecoder(r io.Reader) io.Reader { return &decoder{r: r} }

func (d *decoder) Read(bs []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if len(bs) == 0 {
		return 0, nil
	}

	max := len(bs) * 8
	if max > len(d.buf) {
		max = len(d.buf)
	}
	n, rerr := d.r.Read(d.buf[:max])

	out := 0
	for i := 0; i < n; i++ {
		var bit byte
		switch d.buf[i] {
		case '0':
			bit = 0
		case '1':
			bit = 1
		default:
			d.err = fmt.Errorf("binary: invalid character %q, expected '0' or '1'", d.buf[i])
			return out, d.err
		}
		d.cur = d.cur<<1 | bit
		d.nbits++
		if d.nbits == 8 {
			bs[out] = d.cur
			out++
			d.cur, d.nbits = 0, 0
		}
	}

	if rerr != nil {
		if rerr == io.EOF && d.nbits != 0 {
			d.err = fmt.Errorf("binary: incomplete octet: %v bit(s) remaining", d.nbits)
		} else {
			d.err = rerr
		}
		return out, d.err
	}
	return out, nil
}
