package main

import (
	"database/sql"
	"log"
)

func InsertKey(db *sql.DB, key []byte, exp int64) {
	encryptedKey, err := EncryptPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, encryptedKey, exp)
	if err != nil {
		log.Fatal(err)
	}
}

func GetValidKey(db *sql.DB) ([]byte, int64, int) {
	row := db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp > strftime('%s','now') LIMIT 1`)

	var kid int
	var key []byte
	var exp int64

	err := row.Scan(&kid, &key, &exp)
	if err != nil {
		log.Fatal(err)
	}

	return key, exp, kid
}

func GetExpiredKey(db *sql.DB) ([]byte, int64, int) {
	row := db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp <= strftime('%s','now') LIMIT 1`)

	var kid int
	var key []byte
	var exp int64

	err := row.Scan(&kid, &key, &exp)
	if err != nil {
		log.Fatal(err)
	}

	return key, exp, kid
}

func GetAllValidKeys(db *sql.DB) [][]byte {
	rows, err := db.Query(`SELECT key FROM keys WHERE exp > strftime('%s','now')`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var keys [][]byte

	for rows.Next() {
		var key []byte
		rows.Scan(&key)
		keys = append(keys, key)
	}

	return keys
}
