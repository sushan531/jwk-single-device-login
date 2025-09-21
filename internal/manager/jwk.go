package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"jwk-single-device-login/internal/database"
)

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	GetAnyPrivateKeyWithKeyId(keyPrefix string) (*rsa.PrivateKey, string, error)
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
}

type jwkManager struct {
	jwkSet jwk.Set
	db     *database.DB
	userId int
}

func NewJwkManager() JwkManager {
	db, err := database.NewDB()
	if err != nil {
		// Log the error but continue without database support
		fmt.Printf("Warning: Failed to initialize database: %v\n", err)
		return &jwkManager{}
	}
	return &jwkManager{db: db}
}

// SetUserId sets the user ID for the JWK manager
func (j *jwkManager) SetUserId(userId int) {
	j.userId = userId
}

func (j *jwkManager) InitializeJwkSet(keyPrefix string) error {
	// If we have a database and user ID, try to load from database first
	if j.db != nil && j.userId > 0 {
		jwkSetJSON, err := j.db.GetJWKSet(j.userId)
		if err != nil {
			return fmt.Errorf("failed to get JWK set from database: %w", err)
		}

		// If we found a key for this user, use it
		if jwkSetJSON != "" {
			set, err := jwk.ParseString(jwkSetJSON)
			if err == nil {
				// Check if we already have a key for this device type
				keyID := fmt.Sprintf("key-%s", keyPrefix)
				_, found := set.LookupKeyID(keyID)
				
				if found {
					// We already have a key for this device type
					j.jwkSet = set
					return nil
				} else {
					// We have keys for other device types, but not this one
					// Add a new key for this device type
					privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						return fmt.Errorf("failed to generate private key: %w", err)
					}

					key, err := jwk.Import(privateKey)
					if err != nil {
						return fmt.Errorf("failed to import RSA key into JWK: %w", err)
					}

					if errSettingKeyId := key.Set(jwk.KeyIDKey, keyID); errSettingKeyId != nil {
						return fmt.Errorf("failed to set key ID: %w", errSettingKeyId)
					}

					if errAddingKeyToSet := set.AddKey(key); errAddingKeyToSet != nil {
						return fmt.Errorf("failed to update key set: %w", err)
					}

					j.jwkSet = set

					// Save the updated set back to the database
					updatedJwkSetJSON, err := json.Marshal(set)
					if err != nil {
						return fmt.Errorf("failed to marshal JWK set: %w", err)
					}

					if err := j.db.SaveJWKSet(j.userId, string(updatedJwkSetJSON)); err != nil {
						return fmt.Errorf("failed to save JWK set to database: %w", err)
					}

					return nil
				}
			}
			// If parsing fails, continue to generate a new key set
		}
	}

	// Generate a new key set
	set := jwk.NewSet()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	if errSettingKeyId := key.Set(jwk.KeyIDKey, fmt.Sprintf("key-%s", keyPrefix)); errSettingKeyId != nil {
		return fmt.Errorf("failed to set key ID: %w", errSettingKeyId)
	}

	if errAddingKeyToSet := set.AddKey(key); errAddingKeyToSet != nil {
		return fmt.Errorf("failed to update key set: %w", err)
	}

	j.jwkSet = set

	// Save to database if available
	if j.db != nil && j.userId > 0 {
		jwkSetJSON, err := json.Marshal(set)
		if err != nil {
			return fmt.Errorf("failed to marshal JWK set: %w", err)
		}

		if err := j.db.SaveJWKSet(j.userId, string(jwkSetJSON)); err != nil {
			return fmt.Errorf("failed to save JWK set to database: %w", err)
		}
	}

	return nil
}

func (j *jwkManager) GetAnyPrivateKeyWithKeyId(keyPrefix string) (*rsa.PrivateKey, string, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, "", fmt.Errorf("JWK set is empty or not initialized")
	}

	key, foundKey := j.jwkSet.LookupKeyID(fmt.Sprintf("key-%s", keyPrefix))
	if !foundKey {
		return nil, "", fmt.Errorf("key not found in JWK set")
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, "", fmt.Errorf("failed to export raw key: %w", err)
	}

	var kid string
	if err := key.Get(jwk.KeyIDKey, &kid); err != nil {
		return nil, "", fmt.Errorf("failed to get kid: %w", err)
	}

	return &rsaPrivateKey, kid, nil
}

func (j *jwkManager) GetPublicKeyBy(keyId string) (*rsa.PublicKey, error) {
	if j.jwkSet == nil {
		return nil, errors.New("JWK set not initialized")
	}

	key, found := j.jwkSet.LookupKeyID(keyId)
	if !found {
		return nil, fmt.Errorf("no key found with kid: %s", keyId)
	}

	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Export(key, &rsaPrivateKey); err != nil {
		return nil, fmt.Errorf("failed to export raw key: %w", err)
	}

	return &rsaPrivateKey.PublicKey, nil
}

func (j *jwkManager) GetPublicKeys() ([]*rsa.PublicKey, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, errors.New("JWK set is empty or not initialized")
	}

	publicKeys := make([]*rsa.PublicKey, 0)

	for i := 0; i < j.jwkSet.Len(); i++ {
		key, ok := j.jwkSet.Key(i)
		if !ok {
			continue // skip if key not accessible
		}

		var rawKey interface{}
		if err := jwk.Export(key, &rawKey); err != nil {
			continue // skip keys that fail to export
		}

		switch k := rawKey.(type) {
		case *rsa.PrivateKey:
			publicKeys = append(publicKeys, &k.PublicKey)
		case *rsa.PublicKey:
			publicKeys = append(publicKeys, k)
		}
	}

	if len(publicKeys) == 0 {
		return nil, errors.New("no RSA public keys found in JWK set")
	}

	return publicKeys, nil
}
