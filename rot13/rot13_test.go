package rot13

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"
)

type example struct {
	offset  uint8
	message string
	rotated string
}

var examples = []example{
	{1, "Hello", "Ifmmp"},
	{13, "Attack at dawn", "Nggnpx ng qnja"},
	{26, "This is a test!\n", "This is a test!\n"},
}

func TestRot(t *testing.T) {
	for i, eg := range examples {
		encoded := []byte(eg.message)
		Rot(eg.offset, encoded)
		if !reflect.DeepEqual(encoded, []byte(eg.rotated)) {
			t.Errorf("example %v, wanted Rot%v(%q) -> %q, got %q",
				i+1, eg.offset, eg.message, eg.rotated, string(encoded))
		}
		Rot(26-eg.offset, encoded)
		if !reflect.DeepEqual(encoded, []byte(eg.message)) {
			t.Errorf("example %v, wanted Rot%v(Rot%v(%q)) -> %q, got %q",
				i+1, eg.offset, eg.offset, eg.message, eg.rotated, string(encoded))
		}
	}
}

func TestEncoder(t *testing.T) {
	for i, eg := range examples {
		buf := &bytes.Buffer{}
		w := NewEncoder(eg.offset, buf)
		if n, err := w.Write([]byte(eg.message)); err != nil || n != len(eg.message) {
			t.Fatalf("wrote %v byte(s), err=%v", n, err)
		}
		bs := buf.Bytes()
		if !reflect.DeepEqual(bs, []byte(eg.rotated)) {
			t.Errorf("example %v, wanted Encode%v(%q) -> %q, got %q",
				i+1, eg.offset, eg.message, eg.rotated, string(bs))

		}
	}
}

func TestDecoder(t *testing.T) {
	for i, eg := range examples {
		buf := bytes.NewBufferString(eg.rotated)
		r := NewDecoder(eg.offset, buf)
		bs, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(bs, []byte(eg.message)) {
			t.Errorf("example %v, wanted Decode%v(%q) -> %q, got %q",
				i+1, eg.offset, eg.message, eg.rotated, string(bs))
		}
	}
}
