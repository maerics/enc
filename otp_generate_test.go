package main

import (
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

func runOTPGenerate(t *testing.T, args ...string) (*bytes.Buffer, error) {
	t.Helper()
	cmd := newEncCmd(getDefaultOptions())
	cmd.SetArgs(append([]string{"otp", "generate"}, args...))
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	return out, cmd.Execute()
}

func TestOTPGenerateStdout(t *testing.T) {
	for _, size := range []int{1, 32, 4096} {
		a, err := runOTPGenerate(t, "--size", strconv.Itoa(size))
		if err != nil {
			t.Fatalf("size=%v: unexpected error: %v", size, err)
		}
		if a.Len() != size {
			t.Fatalf("size=%v: got %v byte(s)", size, a.Len())
		}
		b, err := runOTPGenerate(t, "--size", strconv.Itoa(size), "--out", "-")
		if err != nil {
			t.Fatalf("size=%v: unexpected error: %v", size, err)
		}
		if b.Len() != size {
			t.Fatalf("size=%v: got %v byte(s)", size, b.Len())
		}
		if size >= 32 && bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatalf("size=%v: two generated pads are identical", size)
		}
	}
}

func TestOTPGenerateAliasAndArgs(t *testing.T) {
	cmd := newEncCmd(getDefaultOptions())
	cmd.SetArgs([]string{"otp", "gen", "--size", "8"})
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Len() != 8 {
		t.Fatalf("got %v byte(s), wanted 8", out.Len())
	}

	if _, err := runOTPGenerate(t, "--size", "8", "extra"); err == nil {
		t.Fatal("expected an error for a positional arg, got nil")
	}
}

func TestOTPGenerateFile(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")
	stdout, err := runOTPGenerate(t, "--size", "100", "--out", padFilename)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout, got %v byte(s)", stdout.Len())
	}
	info, err := os.Stat(padFilename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 100 {
		t.Fatalf("pad size %v != 100", info.Size())
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("pad mode %o != 0600", mode)
	}
}

func TestOTPGenerateInvalidSize(t *testing.T) {
	for _, args := range [][]string{{}, {"--size", "0"}, {"--size", "-5"}} {
		padFilename := path.Join(t.TempDir(), "otp.pad")
		_, err := runOTPGenerate(t, append(args, "--out", padFilename)...)
		if err == nil || !strings.Contains(err.Error(), `missing or invalid "--size" flag`) {
			t.Fatalf("args=%#v: unexpected error: %v", args, err)
		}
		if _, err := os.Stat(padFilename); !os.IsNotExist(err) {
			t.Fatalf("args=%#v: pad file should not exist, stat err=%v", args, err)
		}
	}
	for _, size := range []string{"1k", "abc"} {
		if _, err := runOTPGenerate(t, "--size", size); err == nil {
			t.Fatalf("size=%q: expected a parse error, got nil", size)
		}
	}
}

func TestOTPGenerateRefusesOverwrite(t *testing.T) {
	padFilename := path.Join(t.TempDir(), "otp.pad")
	original := []byte("existing pad")
	mustWrite(t, padFilename, original)
	_, err := runOTPGenerate(t, "--size", "32", "--out", padFilename)
	if err == nil || !strings.Contains(err.Error(), "failed to open pad file") {
		t.Fatalf("expected an open error, got %v", err)
	}
	got, err := os.ReadFile(padFilename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("existing pad file was modified")
	}
}

func TestOTPGenerateOutputFlags(t *testing.T) {
	dir := t.TempDir()
	globalOut, padOut := path.Join(dir, "global.pad"), path.Join(dir, "out.pad")
	_, err := runOTPGenerate(t, "--size", "8", "-o", globalOut, "--out", padOut)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected a conflict error, got %v", err)
	}
	for _, f := range []string{globalOut, padOut} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%v should not exist, stat err=%v", f, err)
		}
	}

	if _, err := runOTPGenerate(t, "--size", "8", "-o", globalOut); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(globalOut)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 8 || info.Mode().Perm() != 0600 {
		t.Fatalf("got size=%v mode=%o, wanted 8 and 0600", info.Size(), info.Mode().Perm())
	}
}

func TestOTPGenerateDecryptCompat(t *testing.T) {
	for _, deletePad := range []bool{false, true} {
		message := []byte("pre-shared pad message")
		padFilename := path.Join(t.TempDir(), "otp.pad")
		if _, err := runOTPGenerate(t, "--size", strconv.Itoa(len(message)), "--out", padFilename); err != nil {
			t.Fatalf("unexpected generate error: %v", err)
		}
		pad, err := os.ReadFile(padFilename)
		if err != nil {
			t.Fatal(err)
		}

		args := []string{"otp", "--decrypt", "--pad", padFilename}
		if deletePad {
			args = append(args, "--delete-pad")
		}
		cmd := newEncCmd(getDefaultOptions())
		cmd.SetArgs(args)
		cmd.SetIn(bytes.NewReader(xorBytes(message, pad)))
		plaintext := new(bytes.Buffer)
		cmd.SetOut(plaintext)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("unexpected decrypt error: %v", err)
		}
		if !bytes.Equal(plaintext.Bytes(), message) {
			t.Fatalf("wanted %q, got %q", message, plaintext.Bytes())
		}
		_, err = os.Stat(padFilename)
		if deletePad != os.IsNotExist(err) {
			t.Fatalf("deletePad=%v: unexpected pad stat err=%v", deletePad, err)
		}
	}
}

func TestOTPGenerateHelp(t *testing.T) {
	for _, eg := range []struct {
		args []string
		want []string
	}{
		{[]string{"otp", "--help"}, []string{"generate"}},
		{[]string{"otp", "generate", "--help"}, []string{"--size", "--out"}},
	} {
		cmd := newEncCmd(getDefaultOptions())
		cmd.SetArgs(eg.args)
		out := new(bytes.Buffer)
		cmd.SetOut(out)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("args=%#v: unexpected error: %v", eg.args, err)
		}
		for _, w := range eg.want {
			if !strings.Contains(out.String(), w) {
				t.Fatalf("args=%#v: help missing %q:\n%s", eg.args, w, out)
			}
		}
	}
}
