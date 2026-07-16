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
		w := NewEncoder(eg.key, buf, false)
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
		r := NewDecoder(eg.key, buf, false)
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
	w := NewEncoder(nil, buf, false)
	if _, err := w.Write(message); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf.Bytes(), message) {
		t.Errorf("empty key should leave message unchanged, wanted %q, got %q", message, buf.Bytes())
	}
}

func TestNonStrictCyclesShortKey(t *testing.T) {
	eg := examples[1] // key="key" (3 bytes), message is longer than the key.
	buf := &bytes.Buffer{}
	w := NewEncoder(eg.key, buf, false)
	if _, err := w.Write([]byte(eg.message)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf.Bytes(), eg.xored) {
		t.Errorf("non-strict should cycle the key, wanted %x, got %x", eg.xored, buf.Bytes())
	}
}

func TestStrictRejectsShortKeyOnEncode(t *testing.T) {
	eg := examples[1] // key="key" (3 bytes), message is longer than the key.
	buf := &bytes.Buffer{}
	w := NewEncoder(eg.key, buf, true)
	if _, err := w.Write([]byte(eg.message)); err == nil {
		t.Fatal("expected an error when the key is shorter than the message in strict mode, got nil")
	}
}

func TestStrictRejectsShortKeyOnDecode(t *testing.T) {
	eg := examples[1] // key="key" (3 bytes), ciphertext is longer than the key.
	buf := bytes.NewBuffer(eg.xored)
	r := NewDecoder(eg.key, buf, true)
	if _, err := ioutil.ReadAll(r); err == nil {
		t.Fatal("expected an error when the key is shorter than the ciphertext in strict mode, got nil")
	}
}

func TestStrictAllowsExactLengthKey(t *testing.T) {
	key := []byte("exactlen")
	message := []byte("exactlen") // same length as key
	buf := &bytes.Buffer{}
	w := NewEncoder(key, buf, true)
	// Write mutates its argument in place, so pass a copy to keep the
	// original "message" intact for comparison below.
	if _, err := w.Write(append([]byte(nil), message...)); err != nil {
		t.Fatalf("expected no error when the key length matches the message length, got %v", err)
	}

	r := NewDecoder(key, bytes.NewBuffer(buf.Bytes()), true)
	bs, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatalf("expected no error when the key length matches the ciphertext length, got %v", err)
	}
	if !reflect.DeepEqual(bs, message) {
		t.Errorf("wanted %q, got %q", message, bs)
	}
}
