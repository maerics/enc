package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func addJWEDumpCmd(jweCmd *cobra.Command) {
	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Decode a JWE's header, encrypted key, IV, ciphertext, and tag without decrypting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read token from input: %v", err)
			}
			token := strings.TrimSpace(string(input))
			parts := strings.Split(token, ".")
			if len(parts) != 5 {
				return fmt.Errorf("invalid JWE: expected 5 dot-separated parts, got %v", len(parts))
			}

			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				return fmt.Errorf("failed to decode header: %v", err)
			}
			if !json.Valid(headerJSON) {
				return fmt.Errorf("failed to parse header JSON: invalid JSON")
			}

			encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return fmt.Errorf("failed to decode encrypted key: %v", err)
			}
			iv, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				return fmt.Errorf("failed to decode IV: %v", err)
			}
			ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
			if err != nil {
				return fmt.Errorf("failed to decode ciphertext: %v", err)
			}
			tag, err := base64.RawURLEncoding.DecodeString(parts[4])
			if err != nil {
				return fmt.Errorf("failed to decode tag: %v", err)
			}

			out := struct {
				Header       json.RawMessage `json:"header"`
				EncryptedKey string          `json:"encryptedKey"`
				IV           string          `json:"iv"`
				Ciphertext   string          `json:"ciphertext"`
				Tag          string          `json:"tag"`
			}{
				Header:       json.RawMessage(headerJSON),
				EncryptedKey: hex.EncodeToString(encryptedKey),
				IV:           hex.EncodeToString(iv),
				Ciphertext:   hex.EncodeToString(ciphertext),
				Tag:          hex.EncodeToString(tag),
			}

			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to encode output: %v", err)
			}
			w := cmd.OutOrStdout()
			if _, err := w.Write(b); err != nil {
				return fmt.Errorf("failed to write output: %v", err)
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return fmt.Errorf("failed to write output: %v", err)
			}
			return nil
		},
	}

	jweCmd.AddCommand(dumpCmd)
}
