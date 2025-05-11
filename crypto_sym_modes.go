package main

import (
	"errors"
	"strings"
)

// TODO
// --mode={block,cbc,ecb,gcm,...}
// --block (shorthand for "--mode=block")
// --cbc (shorthand for "--mode=cbc")
// --ecb (shorthand for "--mode=ecb")
// --gcm (shorthand for "--mode=gcm" [default])

type cryptoMode string

const (
	cryptoModeBlock cryptoMode = "block"
	cryptoModeCBC   cryptoMode = "cbc"
	cryptoModeCTR   cryptoMode = "ctr"
	cryptoModeECB   cryptoMode = "ecb"
	// cryptoModeOFB     cryptoMode = "ofb"
	cryptoModeGCM cryptoMode = "gcm"
)

var (
	AllCryptoModeStrings = []string{
		string(cryptoModeBlock),
		string(cryptoModeCBC),
		string(cryptoModeCTR),
		string(cryptoModeECB),
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
	switch v {
	case string(cryptoModeBlock), string(cryptoModeCBC), string(cryptoModeCTR), string(cryptoModeECB), string(cryptoModeGCM):
		*e = cryptoMode(v)
		return nil
	default:
		return errors.New("must be one of " + cryptoModesString)
	}
}

// Type is only used in help text
func (e *cryptoMode) Type() string {
	return "mode"
}
