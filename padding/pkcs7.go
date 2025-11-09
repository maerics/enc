package padding

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
	if len(bs) == 0 {
		return bs, nil
	}

	paddingLen := int(bs[len(bs)-1])
	if paddingLen == 0 || paddingLen > len(bs) {
		return bs, nil
	}

	for i := len(bs) - paddingLen; i < len(bs); i++ {
		if bs[i] != byte(paddingLen) {
			return bs, nil
		}
	}

	// Remove the padding
	return bs[:len(bs)-paddingLen], nil
}
