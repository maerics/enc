package main

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestMainHelp(t *testing.T) {
	helpArgs := [][]string{{}, {"-h"}, {"--help"}, {"help"}}

	helpMessages := []*regexp.Regexp{
		regexp.MustCompile(`^Transcode various formats between streams or files.\n`),
		regexp.MustCompile(`Usage:\n  enc \[flags\]\n  enc \[command\]`),
		regexp.MustCompile(`Flags:\n  -`),
		regexp.MustCompile(`\nUse "enc \[command\] --help" for more information about a command.\n$`),
	}

	for _, args := range helpArgs {
		buf := &bytes.Buffer{}
		encCmd := newEncCmd(getDefaultOptions())
		encCmd.SetArgs(args)
		encCmd.SetIn(nil)
		encCmd.SetOut(buf)
		encCmd.Execute()
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

const helloworld = "Hello, World!"

type codecExample struct {
	args   []string
	input  []byte
	output []byte
	errout []byte
}

func TestKnownOutputs(t *testing.T) {
	for i, example := range []codecExample{
		// ascii85
		{[]string{"ascii85"}, []byte(helloworld), []byte("87cURD_*#4DfTZ)+T"), nil},
		{[]string{"ascii85", "-D"}, []byte("87cURD_*#4DfTZ)+T"), []byte(helloworld), nil},

		// base32
		{[]string{"base32"}, []byte(helloworld), []byte("JBSWY3DPFQQFO33SNRSCC==="), nil},
		{[]string{"base32", "-D"}, []byte("JBSWY3DPFQQFO33SNRSCC==="), []byte(helloworld), nil},

		// base58
		{[]string{"base58"}, []byte("OK\n"), []byte("Tdkm"), nil},
		{[]string{"base58", "-D"}, []byte("Tdkm"), []byte("OK\n"), nil},

		// base64
		{[]string{"base64"}, []byte("OK!"), []byte("T0sh"), nil},
		{[]string{"base64", "-D"}, []byte("T0sh"), []byte("OK!"), nil},

		// hex
		{[]string{"hex"}, []byte(helloworld), []byte("48656c6c6f2c20576f726c6421"), nil},
		{[]string{"hex", "--append-newline"}, []byte(helloworld), []byte("48656c6c6f2c20576f726c6421\n"), nil},
		{[]string{"hex", "-n"}, []byte(helloworld), []byte("48656c6c6f2c20576f726c6421\n"), nil},
		{[]string{"hex", "--decode"}, []byte("48656c6c6f2c20576f726c6421"), []byte(helloworld), nil},
		{[]string{"hex", "-D"}, []byte("48656c6c6f2c20576f726c6421"), []byte(helloworld), nil},
		{[]string{"hex", "--decode", "--ignore-whitespace"}, []byte("48656c6c6f2c20576f726c6421\n"), []byte(helloworld), nil},
		{[]string{"hex", "-D", "-w"}, []byte("48656c6c6f2c20576f726c6421\n"), []byte(helloworld), nil},
		{[]string{"hex", "-Dw"}, []byte("48656c6c6f2c20576f726c6421\n"), []byte(helloworld), nil},

		// rot13/caesar
		{[]string{"rot13", "-D", "-r1"}, []byte("BCD\n"), []byte("ABC\n"), nil},
		{[]string{"rot13", "-r1"}, []byte("ABC\n"), []byte("BCD\n"), nil},

		// xor
		{[]string{"xor", "--key=secret"}, []byte("Attack!\n"), []byte{0x32, 0x11, 0x17, 0x13, 0x6, 0x1f, 0x52, 0x6f}, nil},
		{[]string{"xor", "-D", "--key=secret"}, []byte([]byte{0x32, 0x11, 0x17, 0x13, 0x6, 0x1f, 0x52, 0x6f}), []byte("Attack!\n"), nil},
	} {
		encCmd := newEncCmd(getDefaultOptions())
		encCmd.SetArgs(example.args)
		encCmd.SetIn(bytes.NewReader(example.input))
		stdout := new(bytes.Buffer)
		encCmd.SetOut(stdout)
		encCmd.Execute()
		actualStdout := stdout.Bytes()
		if !reflect.DeepEqual(actualStdout, example.output) {
			t.Fatalf("unexpected STDOUT for example #%v (args=%#v, see input):"+
				"\n  wanted: %#v\n     got: %#v",
				i+1, example.args, example.output, actualStdout)
		}
	}
}

const (
	TestInputFilenamePlaceholder  = "__INFILE__"
	TestOutputFilenamePlaceholder = "__OUTFILE__"
)

func getStreamArgCombinations() [][]string {
	return [][]string{
		// Using stdin/stdout streams.
		nil,
		{"--input-file", "-", "--output-file", "-"},
		{"--input-file=-", "--output-file=-"},
		{"-i", "-", "-o", "-"},
		{"-i-", "-o-"},
		// Input file only.
		{"--input-file=__INFILE__"},
		{"--input-file", "__INFILE__"},
		{"-i", "__INFILE__"},
		{"-i__INFILE__"},
		// Output file only.
		{"--output-file=__OUTFILE__"},
		{"--output-file", "__OUTFILE__"},
		{"-o", "__OUTFILE__"},
		{"-o__OUTFILE__"},
		// Both input and output files.
		{"--input-file=__INFILE__", "--output-file=__OUTFILE__"},
		{"--input-file", "__INFILE__", "--output-file", "__OUTFILE__"},
		{"-i", "__INFILE__", "-o", "__OUTFILE__"},
		{"-i__INFILE__", "-o__OUTFILE__"},
	}
}

func TestFileIO(t *testing.T) {
	for i, example := range []codecExample{
		// Streaming
		{[]string{"hex"}, []byte(helloworld), []byte("48656c6c6f2c20576f726c6421"), nil},
		{[]string{"hex", "-D"}, []byte("48656c6c6f2c20576f726c6421"), []byte(helloworld), nil},
		// Buffered
		{[]string{"base58"}, []byte("OK\n"), []byte("Tdkm"), nil},
		{[]string{"base58", "-D"}, []byte("Tdkm"), []byte("OK\n"), nil},
	} {
		for _, ioargs := range getStreamArgCombinations() {
			// Create placeholder input and output files.
			inputFile, err := os.CreateTemp("", "data-input-")
			if err != nil {
				t.Error(err)
			}
			outputFile, err := os.CreateTemp("", "data-output-")
			if err != nil {
				t.Error(err)
			}
			if err := outputFile.Close(); err != nil {
				t.Error(err)
			}
			if err := os.Remove(outputFile.Name()); err != nil {
				t.Error(err)
			}

			// Append each ioarg to the example args and replace the input/output filenames.
			var hasInputFile, hasOutputFile bool
			args := example.args
			for _, ioarg := range ioargs {
				if strings.Contains(ioarg, TestInputFilenamePlaceholder) {
					hasInputFile = true
					ioarg = strings.Replace(ioarg, TestInputFilenamePlaceholder, inputFile.Name(), 1)
					if n, err := inputFile.Write(example.input); err != nil || n != len(example.input) {
						t.Errorf("failed to write input file: err=%v, n=%v (wanted %v)", err, n, len(example.input))
					}
				}
				if strings.Contains(ioarg, TestOutputFilenamePlaceholder) {
					hasOutputFile = true
					ioarg = strings.Replace(ioarg, TestOutputFilenamePlaceholder, outputFile.Name(), 1)
				}
				args = append(args, ioarg)
			}
			if err := inputFile.Close(); err != nil {
				t.Error(err)
			}

			// Run the test.
			encCmd := newEncCmd(getDefaultOptions())
			encCmd.SetArgs(args)

			var stdin io.Reader
			if !hasInputFile {
				stdin = bytes.NewReader(example.input)
				encCmd.SetIn(stdin)
			}

			stdout := new(bytes.Buffer)
			if !hasOutputFile {
				encCmd.SetOut(stdout)
			}

			encCmd.Execute()

			// Ensure the output is as expected.
			var output []byte
			if hasOutputFile {
				output, err = os.ReadFile(outputFile.Name())
				if err != nil {
					t.Error(err)
				}
			} else {
				output = stdout.Bytes()
			}
			if !reflect.DeepEqual(output, example.output) {
				t.Fatalf("unexpected STDOUT for example #%v (args=%#v, ioargs=%#v, see input):"+
					"\n  wanted: %#v\n     got: %#v",
					i+1, example.args, ioargs, example.output, output)
			}
		}
	}
}
