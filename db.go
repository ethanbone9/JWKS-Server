package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

func InitDB() *sql.DB {
	db, err := sql.Open("sqlite", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	return db
}
