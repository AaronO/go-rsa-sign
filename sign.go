package sign

func Sign(key, data []byte) ([]byte, error) {
	signer, err := NewSigner(key)
	if err != nil {
		return nil, err
	}
	return signer.Sign(data)
}

func SignHex(key, data []byte) (string, error) {
	signer, err := NewSigner(key)
	if err != nil {
		return "", err
	}
	return signer.SignHex(data)
}

func SignBase64(key, data []byte) (string, error) {
	signer, err := NewSigner(key)
	if err != nil {
		return "", err
	}
	return signer.SignBase64(data)
}
