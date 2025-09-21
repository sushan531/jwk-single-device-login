# JWK Auth

A Go package for JWT authentication using JWK (JSON Web Key) sets with support for both SQLite and PostgreSQL storage.

## Features

- Generate JWT tokens for users with device-specific keys
- Verify JWT tokens
- Store JWK sets in SQLite or PostgreSQL database
- Support for multiple devices per user
- JWKS endpoint support
- Standalone CLI for testing and management
- Importable as a package for integration with other projects

## Installation

### As a CLI Tool

```bash
# Clone the repository
git clone https://github.com/sushan531/jwkauth.git
cd jwkauth

# Build the binary
go build -o jwkauth

# Install globally (optional)
go install github.com/sushan531/jwkauth@latest
```

### As a Package

```bash
go get github.com/sushan531/jwkauth
```

## Usage

### Standalone CLI

The package includes a command-line interface for JWT operations:

```bash
# Using SQLite (default)
jwkauth menu --db-type=sqlite --db-path=jwk_keys.db

# Using PostgreSQL
jwkauth menu --db-type=postgres --db-conn="postgres://user:password@localhost/dbname?sslmode=disable"
```

Available commands:
- `menu` - Interactive menu for JWT operations
  - Generate tokens
  - Verify tokens
  - Get JWKS (public keys)

CLI Options:
- `--db-type` - Database type (sqlite or postgres)
- `--db-path` - Path to SQLite database file
- `--db-conn` - PostgreSQL connection string

### As a Package

#### Basic Usage

```go
package main

import (
	"fmt"
	"time"

	"github.com/sushan531/jwkauth"
	"github.com/sushan531/jwkauth/model"
)

func main() {
	// Create a new JWKAuth instance with SQLite
	auth := jwkauth.New(jwkauth.Config{
		DBType:          "sqlite",
		DBPath:          "jwk_keys.db",
		TokenExpiration: 24 * time.Hour,
	})

	// Or with PostgreSQL
	// auth := jwkauth.New(jwkauth.Config{
	//     DBType:          "postgres",
	//     DBConnStr:       "postgres://user:password@localhost/dbname?sslmode=disable",
	//     TokenExpiration: 24 * time.Hour,
	// })

	// Create a user
	user := &model.User{
		Id:       123,
		Username: "john.doe",
	}

	// Generate a token for the user on a mobile device
	token, err := auth.GenerateToken(user, "mobile")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated Token: %s\n", token)

	// Verify the token
	verifiedUser, err := auth.VerifyToken(token)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Verified User: %+v\n", verifiedUser)

	// Get public keys for JWKS endpoint
	publicKeys, err := auth.GetPublicKeys()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public Keys: %+v\n", publicKeys)
}
```

#### Integration with a REST API

```go
package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sushan531/jwkauth"
	"github.com/sushan531/jwkauth/model"
)

var auth jwkauth.JWKAuth

func init() {
	// Initialize JWKAuth with SQLite
	auth = jwkauth.New(jwkauth.Config{
		DBType:          "sqlite",
		DBPath:          "jwk_keys.db",
		TokenExpiration: 24 * time.Hour,
	})
}

func main() {
	// Login endpoint
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Parse login credentials
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Device   string `json:"device"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Authenticate user (implement your own logic)
		// ...

		// Generate token
		user := &model.User{
			Id:       123, // Use actual user ID
			Username: creds.Username,
		}
		token, err := auth.GenerateToken(user, creds.Device)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return token
		json.NewEncoder(w).Encode(map[string]string{
			"token": token,
		})
	})

	// JWKS endpoint
	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		keys, err := auth.GetPublicKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	})

	// Protected endpoint
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Extract token from "Bearer <token>"
		tokenString := authHeader[7:]

		// Verify token
		user, err := auth.VerifyToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed with the request
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Protected resource",
			"user":    user,
		})
	})

	http.ListenAndServe(":8080", nil)
}
```

## API Reference

### JWKAuth Interface

```go
type JWKAuth interface {
	GenerateToken(user *model.User, deviceType string) (string, error)
	VerifyToken(token string) (*model.User, error)
	GetPublicKeys() (map[string]interface{}, error)
}
```

### Configuration

```go
type Config struct {
	// Database configuration
	DBType    string // "sqlite" or "postgres"
	DBPath    string // Path to SQLite database file
	DBConnStr string // PostgreSQL connection string
	
	// JWT configuration
	TokenExpiration time.Duration // Default: 24 hours
}
```

## License

MIT