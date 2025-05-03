package main

import "errors"

// TODO
// --mode={block,cbc,ecb,gcm-aead,...}
// --block (shorthand for "--mode=block")
// --cbc (shorthand for "--mode=cbc")
// --ecb (shorthand for "--mode=ecb")
// --gcm-aead (shorthand for "--mode=gcm-aead" [default])

type aesMode string

const (
	aesModeBlock   aesMode = "block"
	aesModeCBC     aesMode = "cbc"
	aesModeECB     aesMode = "ecb"
	aesModeGCMAEAD aesMode = "gcm-aead"

	aesModesString = `"block", "cbc", "ecb", or "gcm-aead"`
)

// String is used both by fmt.Print and by Cobra in help text
func (e *aesMode) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *aesMode) Set(v string) error {
	switch v {
	case string(aesModeBlock), string(aesModeCBC), string(aesModeECB), string(aesModeGCMAEAD):
		*e = aesMode(v)
		return nil
	default:
		return errors.New(`must be one of ` + aesModesString)
	}
}

// Type is only used in help text
func (e *aesMode) Type() string {
	return "mode"
}
