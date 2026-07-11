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

func addJWTDumpCmd(jwtCmd *cobra.Command) {
	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Decode a JWT's header, payload, and signature without verifying",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("failed to read token from input: %v", err)
			}
			token := strings.TrimSpace(string(input))
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				return fmt.Errorf("invalid JWT: expected 3 dot-separated parts, got %v", len(parts))
			}

			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				return fmt.Errorf("failed to decode header: %v", err)
			}
			if !json.Valid(headerJSON) {
				return fmt.Errorf("failed to parse header JSON: invalid JSON")
			}

			payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return fmt.Errorf("failed to decode payload: %v", err)
			}
			if !json.Valid(payloadJSON) {
				return fmt.Errorf("failed to parse payload JSON: invalid JSON")
			}

			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				return fmt.Errorf("failed to decode signature: %v", err)
			}

			out := struct {
				Header    json.RawMessage `json:"header"`
				Payload   json.RawMessage `json:"payload"`
				Signature string          `json:"signature"`
			}{
				Header:    json.RawMessage(headerJSON),
				Payload:   json.RawMessage(payloadJSON),
				Signature: hex.EncodeToString(sig),
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

	jwtCmd.AddCommand(dumpCmd)
}
