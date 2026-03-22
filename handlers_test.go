package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

func newTestServer(t *testing.T) (*sql.DB, *httptest.Server) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate valid key: %v", err)
	}

	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate expired key: %v", err)
	}

	InsertKey(db, EncodePrivateKeyToPEM(validKey), time.Now().Add(2*time.Hour).Unix())
	InsertKey(db, EncodePrivateKeyToPEM(expiredKey), time.Now().Add(-2*time.Hour).Unix())

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)

	srv := httptest.NewServer(mux)

	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})

	return db, srv
}

func getKeyByExpiry(t *testing.T, db *sql.DB, expired bool) (kid int, priv *rsa.PrivateKey) {
	t.Helper()

	var row *sql.Row
	now := time.Now().Unix()

	if expired {
		row = db.QueryRow(`SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1`, now)
	} else {
		row = db.QueryRow(`SELECT kid, key FROM keys WHERE exp > ? LIMIT 1`, now)
	}

	var pemKey []byte
	if err := row.Scan(&kid, &pemKey); err != nil {
		t.Fatalf("scan key: %v", err)
	}

	priv, err := DecodePEMToPrivateKey(pemKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	return kid, priv
}

func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	db, srv := newTestServer(t)

	activeKID, _ := getKeyByExpiry(t, db, false)

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KID != strconv.Itoa(activeKID) {
		t.Fatalf("expected active kid %d, got %s", activeKID, jwks.Keys[0].KID)
	}
}

func TestAuthIssuesActiveJWT(t *testing.T) {
	db, srv := newTestServer(t)

	activeKID, priv := getKeyByExpiry(t, db, false)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	tokenStr := strings.TrimSpace(string(b))
	if tokenStr == "" {
		t.Fatal("empty token")
	}

	verifyToken(t, tokenStr, strconv.Itoa(activeKID), &priv.PublicKey, false)
}

func TestAuthIssuesExpiredJWTWhenQueryPresent(t *testing.T) {
	db, srv := newTestServer(t)

	expiredKID, priv := getKeyByExpiry(t, db, true)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth?expired", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth?expired: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	tokenStr := strings.TrimSpace(string(b))
	if tokenStr == "" {
		t.Fatal("empty token")
	}

	verifyToken(t, tokenStr, strconv.Itoa(expiredKID), &priv.PublicKey, true)
}

func TestJWKSMethodNotAllowed(t *testing.T) {
	_, srv := newTestServer(t)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/.well-known/jwks.json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestAuthMethodNotAllowed(t *testing.T) {
	_, srv := newTestServer(t)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/auth", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestJWKSAliasEndpointWorks(t *testing.T) {
	_, srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
}

func TestAuthReturns500WhenNoActiveKey(t *testing.T) {
	db, srv := newTestServer(t)

	_, err := db.Exec(`DELETE FROM keys WHERE exp > ?`, time.Now().Unix())
	if err != nil {
		t.Fatalf("delete active keys: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestAuthReturns500WhenNoExpiredKey(t *testing.T) {
	db, srv := newTestServer(t)

	_, err := db.Exec(`DELETE FROM keys WHERE exp <= ?`, time.Now().Unix())
	if err != nil {
		t.Fatalf("delete expired keys: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth?expired", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth?expired: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func verifyToken(t *testing.T, tokenStr string, expectedKID string, pub *rsa.PublicKey, expectExpired bool) {
	t.Helper()

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, err := parser.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		if kid != expectedKID {
			t.Fatalf("expected kid %s, got %s", expectedKID, kid)
		}
		return pub, nil
	})
	if err != nil && !expectExpired {
		t.Fatalf("parse/verify failed: %v", err)
	}

	parserNoTime := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	token2, err := parserNoTime.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("parse no-time failed: %v", err)
	}

	claims, ok := token2.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected MapClaims")
	}
	expV, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("expected exp claim float64")
	}
	exp := time.Unix(int64(expV), 0)

	if expectExpired && !exp.Before(time.Now()) {
		t.Fatalf("expected exp in the past, got %v", exp)
	}
	if !expectExpired && exp.Before(time.Now()) {
		t.Fatalf("expected exp in the future, got %v", exp)
	}

	if !expectExpired && (token == nil || !token.Valid) {
		t.Fatalf("expected token valid")
	}
}
