package main

import (
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) (*KeyStore, *httptest.Server) {
	t.Helper()

	ks, err := NewKeyStore(time.Now().Add(2*time.Hour), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)
	return ks, httptest.NewServer(mux)
}

func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	ks, srv := newTestServer(t)
	defer srv.Close()

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
	if jwks.Keys[0].KID != ks.Active().KID {
		t.Fatalf("expected active kid %s, got %s", ks.Active().KID, jwks.Keys[0].KID)
	}
}

func TestAuthIssuesActiveJWT(t *testing.T) {
	ks, srv := newTestServer(t)
	defer srv.Close()

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

	pub := &ks.Active().Priv.PublicKey
	verifyToken(t, tokenStr, ks.Active().KID, pub, false)
}

func TestAuthIssuesExpiredJWTWhenQueryPresent(t *testing.T) {
	ks, srv := newTestServer(t)
	defer srv.Close()

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

	pub := &ks.Expired().Priv.PublicKey
	verifyToken(t, tokenStr, ks.Expired().KID, pub, true)
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
	if err != nil {
		if !expectExpired {
			t.Fatalf("parse/verify failed: %v", err)
		}
	}

	parserNoTime := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	token2, err2 := parserNoTime.Parse(tokenStr, func(tok *jwt.Token) (any, error) { return pub, nil })
	if err2 != nil {
		t.Fatalf("parse no-time failed: %v", err2)
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
