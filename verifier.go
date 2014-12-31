package sign

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
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
