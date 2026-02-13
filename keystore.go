package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type KeyPair struct {
	KID     string
	Expires time.Time
	Priv    *rsa.PrivateKey
}

type KeyStore struct {
	mu      sync.RWMutex
	active  KeyPair
	expired KeyPair
}

func NewKeyStore(activeExp time.Time, expiredExp time.Time) (*KeyStore, error) {
	if !expiredExp.Before(time.Now()) {
		return nil, errors.New("expiredExp must be in the past")
	}
	if !activeExp.After(time.Now()) {
		return nil, errors.New("activeExp must be in the future")
	}

	activePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	expiredPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	ks := &KeyStore{
		active: KeyPair{
			KID:     randomKID(),
			Expires: activeExp,
			Priv:    activePriv,
		},
		expired: KeyPair{
			KID:     randomKID(),
			Expires: expiredExp,
			Priv:    expiredPriv,
		},
	}
	return ks, nil
}

func randomKID() string {
	// 16 random bytes -> 32 hex chars
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (ks *KeyStore) Active() KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.active
}

func (ks *KeyStore) Expired() KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.expired
}

func (ks *KeyStore) UnexpiredPublicJWKs(now time.Time) []JWK {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var keys []JWK
	if ks.active.Expires.After(now) {
		keys = append(keys, RSAPublicKeyToJWK(&ks.active.Priv.PublicKey, ks.active.KID))
	}
	return keys
}
