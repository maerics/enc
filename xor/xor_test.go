package xor

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"
)

type example struct {
	key     []byte
	message string
	xored   []byte
}

var examples = []example{
	{[]byte("\x01"), "Hello", []byte("\x49\x64\x6d\x6d\x6e")},
	{[]byte("key"), "Attack at dawn", []byte("\x2a\x11\x0d\x0a\x06\x12\x4b\x04\x0d\x4b\x01\x18\x1c\x0b")},
	{[]byte("\xff\x00"), "This is a test!\n", []byte("\xab\x68\x96\x73\xdf\x69\x8c\x20\x9e\x20\x8b\x65\x8c\x74\xde\x0a")},
}

func TestEncoder(t *testing.T) {
	for i, eg := range examples {
		buf := &bytes.Buffer{}
		w := NewEncoder(eg.key, buf)
		if n, err := w.Write([]byte(eg.message)); err != nil || n != len(eg.message) {
			t.Fatalf("wrote %v byte(s), err=%v", n, err)
		}
		bs := buf.Bytes()
		if !reflect.DeepEqual(bs, eg.xored) {
			t.Errorf("example %v, wanted Encode(%q, %q) -> %x, got %x",
				i+1, eg.key, eg.message, eg.xored, bs)
		}
	}
}

func TestDecoder(t *testing.T) {
	for i, eg := range examples {
		buf := bytes.NewBuffer(eg.xored)
		r := NewDecoder(eg.key, buf)
		bs, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(bs, []byte(eg.message)) {
			t.Errorf("example %v, wanted Decode(%q, %x) -> %q, got %q",
				i+1, eg.key, eg.xored, eg.message, string(bs))
		}
	}
}

func TestEmptyKey(t *testing.T) {
	message := []byte("unchanged")
	buf := &bytes.Buffer{}
	w := NewEncoder(nil, buf)
	if _, err := w.Write(message); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf.Bytes(), message) {
		t.Errorf("empty key should leave message unchanged, wanted %q, got %q", message, buf.Bytes())
	}
}
