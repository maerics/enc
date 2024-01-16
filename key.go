package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/term"
)

// Attempt to read a password from the terminal without echo.
func getSecretKey(existing string) string {
	log.Printf("OK: -------------- existing=%q", existing)
	if existing == "" && term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, "Enter Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("FATAL: failed to read secret key from stdin")
		}
		fmt.Println()
		log.Printf("OK: -------------- read=%q", string(bytePassword))
		return string(bytePassword)
	}

	return existing
}
