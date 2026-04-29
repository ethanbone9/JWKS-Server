package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
)

func getAESKey() ([]byte, error) {
	key := os.Getenv("NOT_MY_KEY")
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("NOT_MY_KEY must be 16, 24, or 32 bytes")
	}
	return []byte(key), nil
}

func EncryptPrivateKey(plain []byte) ([]byte, error) {
	key, err := getAESKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return ciphertext, nil
}

func DecryptPrivateKey(ciphertext []byte) ([]byte, error) {
	key, err := getAESKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, actualCiphertext, nil)
}
