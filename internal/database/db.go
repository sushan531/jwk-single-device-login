package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// DBType represents the type of database
type DBType string

const (
	SQLite     DBType = "sqlite"
	PostgreSQL DBType = "postgres"
)

// Config holds database configuration
type Config struct {
	DBType    DBType
	DBPath    string // Used for SQLite
	DBConnStr string // Used for PostgreSQL
}

// DB represents a database connection
type DB struct {
	*sql.DB
	config Config
	dbType DBType
}

// NewDB creates a new database connection with the given configuration
func NewDB(config Config) (*DB, error) {
	var db *sql.DB
	var err error
	var dbType = config.DBType

	if dbType == "" {
		dbType = SQLite // Default to SQLite
	}

	switch dbType {
	case SQLite:
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

		// Open the SQLite database
		db, err = sql.Open("sqlite3", config.DBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite database: %w", err)
		}

		// Create the jwk_keys table if it doesn't exist (SQLite syntax)
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS jwk_keys (
				user_id INTEGER PRIMARY KEY,
				jwk_set TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`)

	case PostgreSQL:
		if config.DBConnStr == "" {
			return nil, fmt.Errorf("PostgreSQL connection string is required")
		}

		// Open the PostgreSQL database
		db, err = sql.Open("postgres", config.DBConnStr)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
		}

		// Create the jwk_keys table if it doesn't exist (PostgreSQL syntax)
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS jwk_keys (
				user_id INTEGER PRIMARY KEY,
				jwk_set TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`)

	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create jwk_keys table: %w", err)
	}

	// Check the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{DB: db, config: config, dbType: dbType}, nil
}

// SaveJWKSet saves a JWK set for a user
func (db *DB) SaveJWKSet(userID int, jwkSetJSON string) error {
	var query string
	var args []interface{}

	// Check if the user already has a key
	var count int
	var countQuery string

	if db.dbType == PostgreSQL {
		countQuery = "SELECT COUNT(*) FROM jwk_keys WHERE user_id = $1"
	} else {
		countQuery = "SELECT COUNT(*) FROM jwk_keys WHERE user_id = ?"
	}

	err := db.QueryRow(countQuery, userID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	if count > 0 {
		// Update existing record
		if db.dbType == PostgreSQL {
			query = "UPDATE jwk_keys SET jwk_set = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2"
		} else {
			query = "UPDATE jwk_keys SET jwk_set = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?"
		}
		args = []interface{}{jwkSetJSON, userID}
	} else {
		// Insert new record
		if db.dbType == PostgreSQL {
			query = "INSERT INTO jwk_keys (user_id, jwk_set) VALUES ($1, $2)"
		} else {
			query = "INSERT INTO jwk_keys (user_id, jwk_set) VALUES (?, ?)"
		}
		args = []interface{}{userID, jwkSetJSON}
	}

	_, err = db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to save jwk set: %w", err)
	}

	return nil
}

// GetJWKSet retrieves a JWK set for a user
func (db *DB) GetJWKSet(userID int) (string, error) {
	var jwkSetJSON string
	var query string

	if db.dbType == PostgreSQL {
		query = "SELECT jwk_set FROM jwk_keys WHERE user_id = $1"
	} else {
		query = "SELECT jwk_set FROM jwk_keys WHERE user_id = ?"
	}

	err := db.QueryRow(query, userID).Scan(&jwkSetJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No key found for this user
		}
		return "", fmt.Errorf("failed to get jwk set: %w", err)
	}

	return jwkSetJSON, nil
}