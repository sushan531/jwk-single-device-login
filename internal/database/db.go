package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// Config holds database configuration
type Config struct {
	DBPath string
}

// DB represents a database connection
type DB struct {
	*sql.DB
	config Config
}

// NewDB creates a new database connection with the given configuration
func NewDB(config Config) (*DB, error) {
	if config.DBPath == "" {
		config.DBPath = "jwk_keys.db" // Default path
	}

	// Ensure the database directory exists
	dbDir := filepath.Dir(config.DBPath)
	if dbDir != "." && dbDir != "" {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Open the database
	db, err := sql.Open("sqlite3", config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Check the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create the jwk_keys table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS jwk_keys (
			user_id INTEGER PRIMARY KEY,
			jwk_set TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create jwk_keys table: %w", err)
	}

	return &DB{DB: db, config: config}, nil
}

// SaveJWKSet saves a JWK set for a user
func (db *DB) SaveJWKSet(userID int, jwkSetJSON string) error {
	// Check if the user already has a key
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM jwk_keys WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	if count > 0 {
		// Update existing record
		_, err = db.Exec(
			"UPDATE jwk_keys SET jwk_set = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
			jwkSetJSON, userID,
		)
		if err != nil {
			return fmt.Errorf("failed to update jwk set: %w", err)
		}
	} else {
		// Insert new record
		_, err = db.Exec(
			"INSERT INTO jwk_keys (user_id, jwk_set) VALUES (?, ?)",
			userID, jwkSetJSON,
		)
		if err != nil {
			return fmt.Errorf("failed to insert jwk set: %w", err)
		}
	}

	return nil
}

// GetJWKSet retrieves a JWK set for a user
func (db *DB) GetJWKSet(userID int) (string, error) {
	var jwkSetJSON string
	err := db.QueryRow(
		"SELECT jwk_set FROM jwk_keys WHERE user_id = ?",
		userID,
	).Scan(&jwkSetJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No key found for this user
		}
		return "", fmt.Errorf("failed to get jwk set: %w", err)
	}

	return jwkSetJSON, nil
}