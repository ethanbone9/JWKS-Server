package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	ks, err := NewKeyStore(
		time.Now().Add(24*time.Hour),
		time.Now().Add(-24*time.Hour),
	)
	if err != nil {
		log.Fatalf("failed to initialize keystore: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)

	addr := ":8080"
	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
