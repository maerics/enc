package main

import (
	"bytes"
	"io"
	"testing"
)

func TestWhitespaceIgnoringReader(t *testing.T) {
	for i, eg := range []struct {
		input io.Reader
		bs    []byte
		n     int
		err   error
	}{
		{&bytes.Buffer{}, []byte{}, 0, io.EOF},
		{bytes.NewReader([]byte{0x41, 0x42}), []byte("AB"), 2, nil},
		{bytes.NewReader([]byte{0x0a}), []byte{}, 0, nil},
		{bytes.NewReader([]byte{0x41, 0x0a}), []byte{0x41}, 1, nil},
		{bytes.NewReader([]byte{0x0a, 0x41}), []byte{0x41}, 1, nil},
		{bytes.NewReader([]byte{0x41, 0x0a, 0x42}), []byte("AB"), 2, nil},
		{bytes.NewReader([]byte{0x41, 0x20, 0x42, 0x0a}), []byte("AB"), 2, nil},
		{bytes.NewReader([]byte{0x41, 0x0a, 0x0a}), []byte{0x41}, 1, nil},
		{bytes.NewReader([]byte{0x41, 0x0a, 0x0a, 0x0a}), []byte{0x41}, 1, nil},
		{bytes.NewReader([]byte{0x41, 0x0a, 0x0a, 0x0a, 0x0a}), []byte{0x41}, 1, nil},
		{bytes.NewReader([]byte{0x41, 0x0a, 0x42, 0x0a, 0x43}), []byte("ABC"), 3, nil},
		{bytes.NewReader([]byte{0x41, 0x20, 0x42, 0x09, 0x43, 0x0a}), []byte("ABC"), 3, nil},
	} {
		bs := make([]byte, 0xf)
		wsir := WhitespaceIgnoringReader{eg.input}
		n, err := wsir.Read(bs)
		if n != eg.n {
			t.Errorf("example %d, wanted n=%v, got %v (bs=%#v/%#v)", i+1, eg.n, n, eg.bs, bs)
		}
		if err != eg.err {
			t.Errorf("example %d, wanted err=%v, got %v (bs=%#v/%#v)", i+1, eg.err, err, eg.bs, bs)
		}
		if !bytes.HasPrefix(bs, eg.bs) {
			t.Errorf("example %d, wanted bs ^= %v, got %v", i+1, eg.bs, bs)
		}
	}
}
