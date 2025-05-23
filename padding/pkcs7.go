package padding

import (
	"log"
)

func PadPKCS7(bs []byte, n uint8) ([]byte, error) {
	mod := len(bs) % int(n)
	if mod == 0 {
		return bs, nil
	}

	diff := int(n) - mod
	padded := make([]byte, len(bs)+diff)
	copy(padded, bs)
	for i := diff; i > 0; i-- {
		padded[len(padded)-i] = byte(diff)
	}
	return padded, nil
}

func UnpadPKCS7(bs []byte) ([]byte, error) {
	if len(bs) > 0 {
		pad := bs[len(bs)-1]
		log.Printf("UNPAD: nonzero, pad=%v", pad)
		if len(bs) >= int(pad) {
			log.Printf("UNPAD: len(bs)=%v >= %v", len(bs), pad)
			allEq := true
			for _, b := range bs[int(pad):] {
				if b != pad {
					allEq = false
					break
				}
			}
			log.Printf("UNPAD: allEq=%v, return %v", allEq, bs[:len(bs)-int(pad)])
			if allEq {
				return bs[:len(bs)-int(pad)], nil
			}
		}
	}
	return bs, nil
}
