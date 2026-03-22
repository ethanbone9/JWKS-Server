package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func RSAPublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		KTY: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func EncodePrivateKeyToPEM(priv *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
}

func DecodePEMToPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
