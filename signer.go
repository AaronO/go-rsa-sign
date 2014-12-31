package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

type Signer struct {
	Key *rsa.PrivateKey
}

func NewSigner(pemKey []byte) (*Signer, error) {
	key, err := parseKey(pemKey)
	if err != nil {
		return nil, err
	}

	return &Signer{key}, nil
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA1
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.Key, hash, hashed)
}

func (s *Signer) SignHex(data []byte) (string, error) {
	sig, err := s.Sign(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func (s *Signer) SignBase64(data []byte) (string, error) {
	sig, err := s.Sign(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func parseKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("No PEM block found")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
