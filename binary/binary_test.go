package binary

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type example struct {
	message string
	bits    string
}

var examples = []example{
	{"A", "01000001"},
	{"Hi", "0100100001101001"},
	{"", ""},
}

func TestEncoder(t *testing.T) {
	for i, eg := range examples {
		buf := &bytes.Buffer{}
		w := NewEncoder(buf, false)
		if n, err := w.Write([]byte(eg.message)); err != nil || n != len(eg.message) {
			t.Fatalf("wrote %v byte(s), err=%v", n, err)
		}
		if buf.String() != eg.bits {
			t.Errorf("example %v, wanted Encode(%q) -> %q, got %q", i+1, eg.message, eg.bits, buf.String())
		}
	}
}

func TestEncoderPretty(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewEncoder(buf, true)
	if _, err := w.Write([]byte("Hello, World!")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	want := "01001000 01100101 01101100 01101100 01101111 00101100\n" +
		"00100000 01010111 01101111 01110010 01101100 01100100\n" +
		"00100001\n"
	if buf.String() != want {
		t.Errorf("pretty encode mismatch:\nwant %q\ngot  %q", want, buf.String())
	}
}

func TestEncoderPrettyAcrossWrites(t *testing.T) {
	// Line-wrap state must persist across multiple Write calls, since
	// io.Copy may feed the encoder in arbitrary chunk sizes.
	buf := &bytes.Buffer{}
	w := NewEncoder(buf, true)
	for _, b := range []byte("Hello, World!") {
		if _, err := w.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	want := "01001000 01100101 01101100 01101100 01101111 00101100\n" +
		"00100000 01010111 01101111 01110010 01101100 01100100\n" +
		"00100001\n"
	if buf.String() != want {
		t.Errorf("pretty encode mismatch across writes:\nwant %q\ngot  %q", want, buf.String())
	}
}

func TestEncoderPrettyEmptyNoTrailingNewline(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewEncoder(buf, true)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("pretty encode of empty input should produce no output, got %q", buf.String())
	}
}

func TestDecoder(t *testing.T) {
	for i, eg := range examples {
		r := NewDecoder(strings.NewReader(eg.bits))
		bs, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(bs) != eg.message {
			t.Errorf("example %v, wanted Decode(%q) -> %q, got %q", i+1, eg.bits, eg.message, string(bs))
		}
	}
}

func TestDecoderIncompleteOctet(t *testing.T) {
	r := NewDecoder(strings.NewReader("0100000"))
	_, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("expected an error for an incomplete octet, got nil")
	}
	if !strings.Contains(err.Error(), "incomplete octet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecoderInvalidCharacter(t *testing.T) {
	r := NewDecoder(strings.NewReader("0100200x"))
	_, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("expected an error for an invalid character, got nil")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecoderLargeInput(t *testing.T) {
	message := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 200)
	buf := &bytes.Buffer{}
	if _, err := NewEncoder(buf, false).Write(message); err != nil {
		t.Fatal(err)
	}
	bs, err := io.ReadAll(NewDecoder(buf))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bs, message) {
		t.Fatal("round trip through NewEncoder/NewDecoder did not preserve a large message")
	}
}
