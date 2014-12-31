package sign

func Verify(key, data, sig []byte) error {
	verifier, err := NewVerifier(key)
	if err != nil {
		return err
	}
	return verifier.Verify(data, sig)
}

func VerifyHex(key, data []byte, sig string) error {
	verifier, err := NewVerifier(key)
	if err != nil {
		return err
	}
	return verifier.VerifyHex(data, sig)
}

func VerifyBase64(key, data []byte, sig string) error {
	verifier, err := NewVerifier(key)
	if err != nil {
		return err
	}
	return verifier.VerifyBase64(data, sig)
}
