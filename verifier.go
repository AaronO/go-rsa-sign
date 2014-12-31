package sign

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

type Verifier struct {
	Key *rsa.PublicKey
}

func NewVerifier(pemKey []byte) (*Verifier, error) {
	key, err := parsePublicKey(pemKey)
	if err != nil {
		return nil, err
	}

	return &Verifier{key}, nil
}

func (v *Verifier) Verify(data, sig []byte) error {
	hash := crypto.SHA1
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(v.Key, hash, hashed, sig)
}

func (v *Verifier) VerifyHex(data []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	return v.Verify(data, sig)
}

func (v *Verifier) VerifyBase64(data []byte, sig64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil {
		return err
	}
	return v.Verify(data, sig)
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("No PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Public key's type is '%s', expected 'PUBLIC_KEY'")
	}

	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Could not cast parsed key to *rsa.PublickKey")
	}

	return pubKey, nil
}
