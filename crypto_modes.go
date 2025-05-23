package main

import (
	"errors"
	"slices"
	"strings"
)

// TODO
// --mode={block,cbc,ecb,gcm,...}
// --block (shorthand for "--mode=block")
// --cbc (shorthand for "--mode=cbc")
// etc

type cryptoMode string

const (
	cryptoModeBlock cryptoMode = "block"
	cryptoModeCBC   cryptoMode = "cbc"
	cryptoModeCFB   cryptoMode = "cfb"
	cryptoModeCTR   cryptoMode = "ctr"
	cryptoModeECB   cryptoMode = "ecb"
	cryptoModeOFB   cryptoMode = "ofb"
	cryptoModeGCM   cryptoMode = "gcm"
)

var (
	AllCryptoModeStrings = []string{
		string(cryptoModeBlock),
		string(cryptoModeCBC),
		string(cryptoModeCFB),
		string(cryptoModeCTR),
		string(cryptoModeECB),
		string(cryptoModeOFB),
		string(cryptoModeGCM),
	}

	cryptoModesString = strings.Join(AllCryptoModeStrings, ", ")
)

// String is used both by fmt.Print and by Cobra in help text
func (e *cryptoMode) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *cryptoMode) Set(v string) error {
	if slices.Contains(AllCryptoModeStrings, v) {
		*e = cryptoMode(v)
		return nil
	}
	return errors.New("must be one of " + cryptoModesString)
}

// Type is only used in help text
func (e *cryptoMode) Type() string {
	return "mode"
}
