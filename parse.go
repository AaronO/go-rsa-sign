package sign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	pemData, err := pemParse(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(pemData)
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	pemData, err := pemParse(data, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}

	keyInterface, err := x509.ParsePKIXPublicKey(pemData)
	if err != nil {
		return nil, err
	}

	pubKey, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Could not cast parsed key to *rsa.PublickKey")
	}

	return pubKey, nil
}

func pemParse(data []byte, pemType string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("No PEM block found")
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("Public key's type is '%s', expected '%s'", block.Type, pemType)
	}
	return block.Bytes, nil
}
