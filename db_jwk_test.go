package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

func newTempDB(t *testing.T) *sql.DB {
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

	t.Cleanup(func() {
		_ = db.Close()
	})

	return db
}

func TestEncodeAndDecodePrivateKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pemData := EncodePrivateKeyToPEM(priv)
	if len(pemData) == 0 {
		t.Fatal("expected non-empty PEM")
	}

	decoded, err := DecodePEMToPrivateKey(pemData)
	if err != nil {
		t.Fatalf("decode PEM: %v", err)
	}

	if decoded.N.Cmp(priv.N) != 0 {
		t.Fatal("decoded key does not match original key")
	}
}

func TestRSAPublicKeyToJWK(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk := RSAPublicKeyToJWK(&priv.PublicKey, "123")

	if jwk.KTY != "RSA" {
		t.Fatalf("expected KTY RSA, got %s", jwk.KTY)
	}
	if jwk.Use != "sig" {
		t.Fatalf("expected Use sig, got %s", jwk.Use)
	}
	if jwk.Alg != "RS256" {
		t.Fatalf("expected Alg RS256, got %s", jwk.Alg)
	}
	if jwk.KID != "123" {
		t.Fatalf("expected KID 123, got %s", jwk.KID)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatal("expected non-empty modulus and exponent")
	}
}

func TestInsertAndReadValidAndExpiredKeys(t *testing.T) {
	db := newTempDB(t)

	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate valid key: %v", err)
	}
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate expired key: %v", err)
	}

	InsertKey(db, EncodePrivateKeyToPEM(validKey), time.Now().Add(1*time.Hour).Unix())
	InsertKey(db, EncodePrivateKeyToPEM(expiredKey), time.Now().Add(-1*time.Hour).Unix())

	validPEM, validExp, validKID := GetValidKey(db)
	if len(validPEM) == 0 {
		t.Fatal("expected valid key PEM")
	}
	if validExp <= time.Now().Unix() {
		t.Fatal("expected valid key expiration in future")
	}
	if validKID == 0 {
		t.Fatal("expected non-zero valid kid")
	}

	expiredPEM, expiredExp, expiredKID := GetExpiredKey(db)
	if len(expiredPEM) == 0 {
		t.Fatal("expected expired key PEM")
	}
	if expiredExp > time.Now().Unix() {
		t.Fatal("expected expired key expiration in past")
	}
	if expiredKID == 0 {
		t.Fatal("expected non-zero expired kid")
	}

	validKeys := GetAllValidKeys(db)
	if len(validKeys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(validKeys))
	}
}

func TestSignJWTActiveAndExpired(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	activeExp := time.Now().Add(1 * time.Hour).Unix()
	tokenStr, err := signJWT(priv, 42, activeExp, false)
	if err != nil {
		t.Fatalf("sign active JWT: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty active token")
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	token, err := parser.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse active token: %v", err)
	}

	if token.Header["kid"] != "42" {
		t.Fatalf("expected kid 42, got %v", token.Header["kid"])
	}

	expiredExp := time.Now().Add(-1 * time.Hour).Unix()
	expiredTokenStr, err := signJWT(priv, 99, expiredExp, true)
	if err != nil {
		t.Fatalf("sign expired JWT: %v", err)
	}
	if expiredTokenStr == "" {
		t.Fatal("expected non-empty expired token")
	}
}

func TestSeedKeysOnlySeedsOnce(t *testing.T) {
	db := newTempDB(t)

	seedKeys(db)
	seedKeys(db)

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count)
	if err != nil {
		t.Fatalf("count keys: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected exactly 2 seeded keys, got %d", count)
	}
}

func TestInitDBCreatesDatabaseFileAndTable(t *testing.T) {
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir tempDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWD)
	}()

	db := InitDB()
	defer db.Close()

	dbPath := filepath.Join(tempDir, "totally_not_my_privateKeys.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected DB file to exist: %v", err)
	}

	var name string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='keys'`).Scan(&name)
	if err != nil {
		t.Fatalf("expected keys table to exist: %v", err)
	}
	if name != "keys" {
		t.Fatalf("expected table name keys, got %s", name)
	}
}

func TestGetValidKeyAndExpiredKeyKidsDiffer(t *testing.T) {
	db := newTempDB(t)

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

	_, _, validKID := GetValidKey(db)
	_, _, expiredKID := GetExpiredKey(db)

	if validKID == expiredKID {
		t.Fatal("expected different kids for valid and expired keys")
	}

	if strconv.Itoa(validKID) == "" || strconv.Itoa(expiredKID) == "" {
		t.Fatal("expected kids to be convertible to strings")
	}
}
