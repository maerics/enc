package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func addOTPCommand(rootCmd *cobra.Command, o *Options) {
	short := "Encrypt input using a freshly generated one-time pad"
	if o.Decode {
		short = "Decrypt input using a previously generated one-time pad"
	}

	cmd := &cobra.Command{
		Use:     "otp",
		Aliases: []string{"perfect"},
		Short:   short,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.Decode {
				return otpDecrypt(cmd, o)
			}
			return otpEncrypt(cmd, o)
		},
	}

	cmd.Flags().StringVarP(&o.PadFilename, FlagNamePad, "p", "",
		"pad file path: written on encrypt, read on decrypt (required)")
	cmd.Flags().BoolVar(&o.ForcePad, "force", false,
		"allow overwriting an existing pad file when encrypting (dangerous: reusing a pad destroys one-time-pad security)")
	cmd.Flags().BoolVar(&o.DeletePad, "delete-pad", false,
		"delete the pad file after a successful decrypt (reuse destroys one-time-pad security)")

	rootCmd.AddCommand(cmd)
}

func otpEncrypt(cmd *cobra.Command, o *Options) error {
	if err := checkPadFilename(o.PadFilename); err != nil {
		return err
	}

	plaintext, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %v", err)
	}

	pad := make([]byte, len(plaintext))
	if _, err := io.ReadFull(rand.Reader, pad); err != nil {
		return fmt.Errorf("failed to generate pad: %v", err)
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if o.ForcePad {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	padFile, err := os.OpenFile(o.PadFilename, flags, 0600)
	if err != nil {
		return fmt.Errorf("failed to open pad file %q for writing (use --force to overwrite an existing pad, but reusing a pad destroys one-time-pad security): %v",
			o.PadFilename, err)
	}
	if _, err := padFile.Write(pad); err != nil {
		padFile.Close()
		return fmt.Errorf("failed to write pad file: %v", err)
	}
	if err := padFile.Close(); err != nil {
		return fmt.Errorf("failed to close pad file: %v", err)
	}

	if _, err := cmd.OutOrStdout().Write(xorBytes(plaintext, pad)); err != nil {
		return fmt.Errorf("failed to write ciphertext: %v", err)
	}
	return nil
}

func otpDecrypt(cmd *cobra.Command, o *Options) error {
	if err := checkPadFilename(o.PadFilename); err != nil {
		return err
	}

	// Read the ciphertext (blocking until stdin EOF) before touching the
	// pad file. In a shell pipeline like "enc otp --pad=X | dec otp
	// --pad=X" both processes start concurrently, and encryption always
	// finishes writing the pad before it writes any ciphertext; waiting
	// for EOF here guarantees the pad write already happened, avoiding a
	// race where decrypt opens the pad before encrypt has created it.
	ciphertext, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %v", err)
	}

	pad, err := os.ReadFile(o.PadFilename)
	if err != nil {
		return fmt.Errorf("failed to read pad file: %v", err)
	}

	if len(pad) != len(ciphertext) {
		return fmt.Errorf("pad length (%v byte(s)) does not match ciphertext length (%v byte(s))", len(pad), len(ciphertext))
	}

	if _, err := cmd.OutOrStdout().Write(xorBytes(ciphertext, pad)); err != nil {
		return fmt.Errorf("failed to write plaintext: %v", err)
	}

	if o.DeletePad {
		if err := os.Remove(o.PadFilename); err != nil {
			return fmt.Errorf("decrypted successfully but failed to delete pad file %q: %v", o.PadFilename, err)
		}
	}
	return nil
}

func checkPadFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf(`missing required "--%v" flag`, FlagNamePad)
	}
	if filename == "-" {
		return fmt.Errorf(`the "--%v" flag does not support "-" (stdin); provide a file path`, FlagNamePad)
	}
	return nil
}

func xorBytes(data, pad []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ pad[i]
	}
	return out
}
