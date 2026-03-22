package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"log"
	"net/http"
	"time"
)

func seedKeys(db *sql.DB) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count)
	if err != nil {
		log.Fatalf("failed to count keys: %v", err)
	}

	if count > 0 {
		return
	}

	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate valid key: %v", err)
	}

	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate expired key: %v", err)
	}

	InsertKey(db, EncodePrivateKeyToPEM(validKey), time.Now().Add(1*time.Hour).Unix())
	InsertKey(db, EncodePrivateKeyToPEM(expiredKey), time.Now().Add(-1*time.Hour).Unix())
}

func main() {
	db := InitDB()
	defer db.Close()

	seedKeys(db)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)

	addr := ":8080"
	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
