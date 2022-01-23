package enc

import (
	"encoding/json"
	"fmt"
)

type Options struct {
	Decode bool

	CheckVersion *byte

	FormatJSON bool
}

func mustJSON(v interface{}) []byte {
	bs, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Errorf("failed to marshal JSON: %w", err))
	}
	return bs
}
