package main

import (
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func RegisterRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler(db))
	mux.HandleFunc("/jwks", jwksHandler(db))
	mux.HandleFunc("/auth", authHandler(db))
}

func jwksHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		rows, err := db.Query(`SELECT kid, key FROM keys WHERE exp > ?`, time.Now().Unix())
		if err != nil {
			http.Error(w, "failed to read keys", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var jwkKeys []JWK

		for rows.Next() {
			var kid int
			var pemKey []byte

			if err := rows.Scan(&kid, &pemKey); err != nil {
				http.Error(w, "failed to scan key", http.StatusInternalServerError)
				return
			}

			privKey, err := DecodePEMToPrivateKey(pemKey)
			if err != nil {
				http.Error(w, "failed to decode key", http.StatusInternalServerError)
				return
			}

			jwk := RSAPublicKeyToJWK(&privKey.PublicKey, strconv.Itoa(kid))
			jwkKeys = append(jwkKeys, jwk)
		}

		resp := JWKS{Keys: jwkKeys}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func authHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		issueExpired := false
		if _, ok := r.URL.Query()["expired"]; ok {
			issueExpired = true
		}

		var (
			kid    int
			keyPEM []byte
			exp    int64
		)

		if issueExpired {
			err := db.QueryRow(
				`SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1`,
				time.Now().Unix(),
			).Scan(&kid, &keyPEM, &exp)
			if err != nil {
				http.Error(w, "no expired signing key available", http.StatusInternalServerError)
				return
			}
		} else {
			err := db.QueryRow(
				`SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1`,
				time.Now().Unix(),
			).Scan(&kid, &keyPEM, &exp)
			if err != nil {
				http.Error(w, "no unexpired signing key available", http.StatusInternalServerError)
				return
			}
		}

		privKey, err := DecodePEMToPrivateKey(keyPEM)
		if err != nil {
			http.Error(w, "failed to decode private key", http.StatusInternalServerError)
			return
		}

		tokenStr, err := signJWT(privKey, kid, exp, issueExpired)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(tokenStr))
	}
}

func signJWT(privKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Public() crypto.PublicKey
}, kid int, keyExp int64, issueExpired bool) (string, error) {
	now := time.Now()

	exp := time.Unix(keyExp, 0)
	if !issueExpired {
		expCandidate := now.Add(5 * time.Minute)
		if expCandidate.Before(exp) {
			exp = expCandidate
		}
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = strconv.Itoa(kid)

	s, err := tok.SignedString(privKey)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("empty token")
	}
	return s, nil
}
