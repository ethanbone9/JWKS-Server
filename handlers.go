package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func RegisterRoutes(mux *http.ServeMux, ks *KeyStore) {
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler(ks))
	mux.HandleFunc("/jwks", jwksHandler(ks))

	mux.HandleFunc("/auth", authHandler(ks))
}

func jwksHandler(ks *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		keys := ks.UnexpiredPublicJWKs(time.Now())
		resp := JWKS{Keys: keys}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func authHandler(ks *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		issueExpired := false
		if _, ok := r.URL.Query()["expired"]; ok {
			issueExpired = true
		}

		var kp KeyPair
		if issueExpired {
			kp = ks.Expired()
		} else {
			kp = ks.Active()
		}

		if !issueExpired && !kp.Expires.After(time.Now()) {
			http.Error(w, "no unexpired signing key available", http.StatusInternalServerError)
			return
		}

		tokenStr, err := signJWT(kp, issueExpired)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(tokenStr))
	}
}

func signJWT(kp KeyPair, issueExpired bool) (string, error) {
	now := time.Now()

	exp := kp.Expires
	if !issueExpired {

		expCandidate := now.Add(5 * time.Minute)
		if expCandidate.Before(kp.Expires) {
			exp = expCandidate
		}
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kp.KID

	s, err := tok.SignedString(kp.Priv)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("empty token")
	}
	return s, nil
}
