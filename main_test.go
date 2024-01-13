package main

import (
	"bytes"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestMainHelp(t *testing.T) {
	helpArgs := [][]string{{}, {"-h"}, {"--help"}}

	helpMessages := []*regexp.Regexp{
		regexp.MustCompile(`^Transcode various formats between stdin and stdout.\n`),
		regexp.MustCompile(`Usage:\n  enc \[command\]`),
		regexp.MustCompile(`Flags:\n  -`),
		regexp.MustCompile(`\nUse "enc \[command\] --help" for more information about a command.\n$`),
	}

	for _, args := range helpArgs {
		buf := &bytes.Buffer{}
		encCmd = newEncCmd(getDefaultOptions())
		encCmd.SetArgs(args)
		encCmd.SetIn(nil)
		encCmd.SetOut(buf)
		main()
		output := buf.String()

		for _, helpMessage := range helpMessages {
			if !helpMessage.MatchString(output) {
				t.Fatalf(
					"unexpected help message\n:  wanted: %q\n     got: %q",
					helpMessage.String(), output)
			}
		}
	}
}
func TestKnownOutputs(t *testing.T) {
	for i, example := range []struct {
		args   []string
		input  io.Reader
		stdout []byte
		stderr []byte
	}{
		{[]string{"hex"}, strings.NewReader("OK\n"), []byte("4f4b0a"), nil},
		{[]string{"hex", "--decode", "--ignore-whitespace"}, strings.NewReader("4f4b0a"), []byte("OK\n"), nil},
		{[]string{"hex", "-Dw"}, strings.NewReader("4f4b0a"), []byte("OK\n"), nil},
		{[]string{"-D", "hex", "-w"}, strings.NewReader("4f4b0a"), []byte("OK\n"), nil},
		{[]string{"--decode", "hex", "--ignore-whitespace"}, strings.NewReader("4f4b0a"), []byte("OK\n"), nil},
		{[]string{"xor", "--key=secret"}, strings.NewReader("Attack!\n"), []byte{0x32, 0x11, 0x17, 0x13, 0x6, 0x1f, 0x52, 0x6f}, nil},
		{[]string{"xor", "-D", "--key=secret"}, bytes.NewReader([]byte{0x32, 0x11, 0x17, 0x13, 0x6, 0x1f, 0x52, 0x6f}), []byte("Attack!\n"), nil},
		{[]string{"base58"}, strings.NewReader("OK\n"), []byte("Tdkm"), nil},
		{[]string{"base58", "-D"}, strings.NewReader("Tdkm"), []byte("OK\n"), nil},
		{[]string{"base58", "-Dw"}, strings.NewReader("Tdkm\n"), []byte("OK\n"), nil},
		{[]string{"rot13", "-r1"}, strings.NewReader("ABC\n"), []byte("BCD\n"), nil},
		{[]string{"rot13", "-D", "-r1"}, strings.NewReader("BCD\n"), []byte("ABC\n"), nil},
	} {
		encCmd = newEncCmd(getDefaultOptions())
		encCmd.SetArgs(example.args)
		encCmd.SetIn(example.input)
		stdout := new(bytes.Buffer)
		encCmd.SetOut(stdout)
		stderr := new(bytes.Buffer)
		encCmd.SetErr(stderr)
		main()
		actualStdout := stdout.Bytes()
		actualStderr := stderr.Bytes()
		if !reflect.DeepEqual(actualStdout, example.stdout) {
			t.Fatalf("unexpected STDOUT for example #%v (args=%#v, see input):"+
				"\n  wanted: %#v\n     got: %#v",
				i+1, example.args, example.stdout, actualStdout)
		}
		if !reflect.DeepEqual(actualStderr, example.stderr) {
			t.Fatalf("unexpected STDERR for example #%v (args=%#v, see input):"+
				"\n  wanted: %#v\n     got: %#v",
				i+1, example.args, example.stderr, actualStderr)
		}
	}
}
