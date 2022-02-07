package rot13

import (
	"io"
)

const Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type rot13 struct {
	offset uint8
	r      io.Reader
	w      io.Writer
}

func NewDecoder(offset uint8, r io.Reader) io.Reader {
	return rot13{offset: offset % 26, r: r}
}

func NewEncoder(offset uint8, w io.Writer) io.Writer {
	return rot13{offset: offset % 26, w: w}
}

func Rot(offset uint8, bs []byte) {
	for i, b := range bs {
		if 'A' <= b && b <= 'Z' {
			b2 := Alphabet[((b-'A')+offset)%26]
			bs[i] = b2
			// log.Printf("ROT13: UPPER: offset=%v, b=%v (%q), b2=%v (%q)", r13.offset, b, string([]byte{b}), b2, string([]byte{b2}))
		} else if 'a' <= b && b <= 'z' {
			b2 := Alphabet[(((b-'a'+26)+offset)%26)+26]
			bs[i] = b2
			// log.Printf("ROT13: upper: offset=%v, b=%v (%q), b2=%v (%q)", r13.offset, b, string([]byte{b}), b2, string([]byte{b2}))
		}
	}
}

func (r13 rot13) Read(bs []byte) (int, error) {
	n, err := r13.r.Read(bs)
	if err == nil {
		Rot(26-r13.offset, bs)
	}
	return n, err
}

func (r13 rot13) Write(bs []byte) (int, error) {
	Rot(r13.offset, bs)
	return r13.w.Write(bs)
}
