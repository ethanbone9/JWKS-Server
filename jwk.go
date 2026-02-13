package main

import (
	"crypto/rsa"
	"encoding/base64"
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
