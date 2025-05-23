package padding

import (
	"bytes"
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	for i, eg := range []struct {
		input    []byte
		length   uint8
		expected []byte
		err      error
	}{
		{[]byte{}, 32, []byte{}, nil},
		{[]byte{}, 16, []byte{}, nil},
		{[]byte{}, 8, []byte{}, nil},
		{[]byte{}, 4, []byte{}, nil},
		{[]byte("a"), 4, []byte("a\x03\x03\x03"), nil},
		{[]byte("ab"), 4, []byte("ab\x02\x02"), nil},
		{[]byte("abc"), 4, []byte("abc\x01"), nil},
		{[]byte("abcd"), 4, []byte("abcd"), nil},
		{[]byte("0000abcd"), 4, []byte("0000abcd"), nil},
		{[]byte("0000abc"), 4, []byte("0000abc\x01"), nil},
		{[]byte("0000ab"), 4, []byte("0000ab\x02\x02"), nil},
		{[]byte("deadbeefx"), 8, []byte("deadbeefx\x07\x07\x07\x07\x07\x07\x07"), nil},
		{[]byte("deadbeef"), 8, []byte("deadbeef"), nil},
		{[]byte("deadbee"), 8, []byte("deadbee\x01"), nil},
		{[]byte("deadbe"), 8, []byte("deadbe\x02\x02"), nil},
	} {
		actual, actualErr := PadPKCS7(eg.input, eg.length)
		if eg.err != nil {
			if actualErr == nil {
				t.Fatalf("example %v\ngot no error but expected %q", i, eg.err.Error())
			} else if eg.err.Error() != actualErr.Error() {
				t.Fatalf("example %v\nunexpected error\nwanted %v\nactual %v", i, eg.err, actualErr)
			}
		} else if actualErr != nil {
			t.Fatalf("example %v\nunexpected error %q", i, actualErr.Error())
		} else if !bytes.Equal(actual, eg.expected) {
			t.Fatalf("example %v\nunexpected output\nwanted %v\nactual %v", i, eg.expected, actual)
		}
	}
}

func xTestUnpadPKCS7(t *testing.T) {
	for i, eg := range []struct {
		input    []byte
		expected []byte
		err      error
	}{
		{[]byte{}, []byte{}, nil},
		{[]byte("a\x03\x03\x03"), []byte("a"), nil},
		{[]byte("ab\x02\x02"), []byte("ab"), nil},
		{[]byte("abc\x01"), []byte("abc"), nil},
		{[]byte("abcd"), []byte("abcd"), nil},
		{[]byte("0000abcd"), []byte("0000abcd"), nil},
		{[]byte("0000abc"), []byte("0000abc\x01"), nil},
		{[]byte("0000ab\x02\x02"), []byte("0000ab"), nil},
		{[]byte("deadbeefx\x07\x07\x07\x07\x07\x07\x07"), []byte("deadbeefx"), nil},
		{[]byte("deadbeef"), []byte("deadbeef"), nil},
		{[]byte("deadbee\x01"), []byte("deadbee"), nil},
		{[]byte("deadbe\x02\x02"), []byte("deadbe"), nil},
	} {
		actual, actualErr := UnpadPKCS7(eg.input)
		if eg.err != nil {
			if actualErr == nil {
				t.Fatalf("example %v\ngot no error but expected %q", i, eg.err.Error())
			} else if eg.err.Error() != actualErr.Error() {
				t.Fatalf("example %v\nunexpected error\nwanted %v\nactual %v", i, eg.err, actualErr)
			}
		} else if actualErr != nil {
			t.Fatalf("example %v\nunexpected error %q", i, actualErr.Error())
		} else if !bytes.Equal(actual, eg.expected) {
			t.Fatalf("example %v\nunexpected output\nwanted %v\nactual %v", i, eg.expected, actual)
		}
	}
}
