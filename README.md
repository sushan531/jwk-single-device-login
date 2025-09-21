# JWK Auth

A Go package for JWT authentication using JWK (JSON Web Key) sets with SQLite storage.

## Features

- Generate JWT tokens for users with device-specific keys
- Verify JWT tokens
- Store JWK sets in SQLite database
- Support for multiple devices per user
- JWKS endpoint support

## Installation

```bash
go get github.com/sushan531/jwkauth
```

## Usage

### Basic Usage

```go
package main

import (
	"fmt"
	"time"

	"github.com/sushan531/jwkauth"
	"github.com/sushan531/jwkauth/model"
)

func main() {
	// Create a new JWKAuth instance
	auth := jwkauth.New(jwkauth.Config{
		DBPath:          "jwk_keys.db",
		TokenExpiration: 24 * time.Hour,
	})

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

### Integration with a REST API

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
	// Initialize JWKAuth
	auth = jwkauth.New(jwkauth.Config{
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

		// Validate credentials (replace with your own logic)
		if creds.Username != "john.doe" || creds.Password != "password" {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Create user
		user := &model.User{
			Id:       123,
			Username: creds.Username,
		}

		// Generate token
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

	// Protected endpoint
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Verify token
		user, err := auth.VerifyToken(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Return user info
		json.NewEncoder(w).Encode(user)
	})

	// JWKS endpoint
	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		// Get public keys
		publicKeys, err := auth.GetPublicKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Convert to JWKS format
		jwks := map[string]interface{}{
			"keys": publicKeys,
		}

		// Return JWKS
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// Start server
	http.ListenAndServe(":8080", nil)
}
```

## Configuration

The `Config` struct allows you to customize the behavior of the package:

- `DBPath`: Path to the SQLite database file (default: "jwk_keys.db")
- `TokenExpiration`: Duration until tokens expire (default: 24 hours)

## License

MIT