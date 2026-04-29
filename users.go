package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type RegisterResponse struct {
	Password string `json:"password"`
}

func generatePassword() string {
	return uuid.NewString()
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		1,
		64*1024,
		4,
		32,
	)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	return saltB64 + "$" + hashB64, nil
}

func insertUser(db *sql.DB, username, email, passwordHash string) error {
	_, err := db.Exec(
		`INSERT INTO users(username, email, password_hash) VALUES(?, ?, ?)`,
		username,
		email,
		passwordHash,
	)
	return err
}

func getUserIDByUsername(db *sql.DB, username string) (int, error) {
	var id int
	err := db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	return id, err
}

func logAuthRequest(db *sql.DB, requestIP string, userID int) error {
	if userID == 0 {
		_, err := db.Exec(
			`INSERT INTO auth_logs(request_ip) VALUES(?)`,
			requestIP,
		)
		return err
	}

	_, err := db.Exec(
		`INSERT INTO auth_logs(request_ip, user_id) VALUES(?, ?)`,
		requestIP,
		userID,
	)
	return err
}
