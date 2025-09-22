package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKDataset represents the complete dataset for database storage
type JWKDataset struct {
	ID         string                 `json:"id"`
	KeySetData []byte                 `json:"key_set_data"`
	Metadata   *JWKMetadata           `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	Version    string                 `json:"version"`
	Checksum   string                 `json:"checksum"`
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
}

// JWKMetadata contains metadata about the JWK set
type JWKMetadata struct {
	KeyPrefix   string            `json:"key_prefix"`
	Algorithm   string            `json:"algorithm"`
	KeySize     int               `json:"key_size"`
	KeyCount    int               `json:"key_count"`
	Purpose     string            `json:"purpose"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	Description string            `json:"description,omitempty"`
}

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	GetAnyPrivateKeyWithKeyId(keyPrefix string) (*rsa.PrivateKey, string, error)
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	// New methods for database serialization/deserialization
	SerializeForDatabase(id string, metadata *JWKMetadata) (*JWKDataset, error)
	DeserializeFromDatabase(dataset *JWKDataset) error
}

type jwkManager struct {
	jwkSet jwk.Set
}

func NewJwkManager() JwkManager {
	return &jwkManager{}
}

func (j *jwkManager) InitializeJwkSet(keyPrefix string) error {
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
	return nil
}

func (j *jwkManager) GetAnyPrivateKeyWithKeyId(keyPrefix string) (*rsa.PrivateKey, string, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, "", fmt.Errorf("JWK set is empty or not initialized")
	}

	// you can place your logic to fetch random key
	// it could be as simple as randomInt from (0 to j.jwkSet.Len() - 1)
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

// SerializeForDatabase converts the current JWK set into a complete dataset for database storage
func (j *jwkManager) SerializeForDatabase(id string, metadata *JWKMetadata) (*JWKDataset, error) {
	if j.jwkSet == nil {
		return nil, errors.New("JWK set not initialized")
	}

	// Serialize the JWK set to JSON
	keySetData, err := json.Marshal(j.jwkSet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	// Generate checksum for data integrity
	checksum, err := j.generateChecksum(keySetData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate checksum: %w", err)
	}

	// Set default metadata if not provided
	if metadata == nil {
		metadata = &JWKMetadata{
			Algorithm: "RS256",
			KeySize:   2048,
			KeyCount:  j.jwkSet.Len(),
			Purpose:   "JWT signing and verification",
		}
	} else {
		// Update key count to reflect current state
		metadata.KeyCount = j.jwkSet.Len()
	}

	// Create the complete dataset
	dataset := &JWKDataset{
		ID:         id,
		KeySetData: keySetData,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Version:    "1.0.0",
		Checksum:   checksum,
	}

	return dataset, nil
}

// DeserializeFromDatabase reconstructs the JWK set from a database dataset
func (j *jwkManager) DeserializeFromDatabase(dataset *JWKDataset) error {
	if dataset == nil {
		return errors.New("dataset cannot be nil")
	}

	if len(dataset.KeySetData) == 0 {
		return errors.New("key set data is empty")
	}

	// Verify data integrity using checksum
	if err := j.verifyChecksum(dataset.KeySetData, dataset.Checksum); err != nil {
		return fmt.Errorf("data integrity check failed: %w", err)
	}

	// Check if dataset has expired
	if dataset.ExpiresAt != nil && time.Now().After(*dataset.ExpiresAt) {
		return errors.New("JWK dataset has expired")
	}

	// Deserialize the JWK set from JSON
	var jwkSet jwk.Set
	if err := json.Unmarshal(dataset.KeySetData, &jwkSet); err != nil {
		return fmt.Errorf("failed to unmarshal JWK set: %w", err)
	}

	// Validate the reconstructed JWK set
	if err := j.validateJWKSet(jwkSet, dataset.Metadata); err != nil {
		return fmt.Errorf("JWK set validation failed: %w", err)
	}

	// Set the reconstructed JWK set
	j.jwkSet = jwkSet

	return nil
}

// generateChecksum creates a SHA-256 checksum for data integrity verification
func (j *jwkManager) generateChecksum(data []byte) (string, error) {
	hash := fmt.Sprintf("%x", data) // Simple hash for demonstration
	// In production, use crypto/sha256 for proper checksums
	return hash[:32], nil // Return first 32 characters as checksum
}

// verifyChecksum verifies the integrity of the data using the provided checksum
func (j *jwkManager) verifyChecksum(data []byte, expectedChecksum string) error {
	actualChecksum, err := j.generateChecksum(data)
	if err != nil {
		return fmt.Errorf("failed to generate checksum for verification: %w", err)
	}

	if actualChecksum != expectedChecksum {
		return errors.New("checksum mismatch - data may be corrupted")
	}

	return nil
}

// validateJWKSet performs validation on the reconstructed JWK set
func (j *jwkManager) validateJWKSet(jwkSet jwk.Set, metadata *JWKMetadata) error {
	if jwkSet == nil {
		return errors.New("JWK set is nil")
	}

	if jwkSet.Len() == 0 {
		return errors.New("JWK set is empty")
	}

	// Validate key count matches metadata
	if metadata != nil && metadata.KeyCount != jwkSet.Len() {
		return fmt.Errorf("key count mismatch: expected %d, got %d", metadata.KeyCount, jwkSet.Len())
	}

	// Validate each key in the set
	for i := 0; i < jwkSet.Len(); i++ {
		key, ok := jwkSet.Key(i)
		if !ok {
			return fmt.Errorf("failed to access key at index %d", i)
		}

		// Check if key has required fields
		var keyID string
		if err := key.Get(jwk.KeyIDKey, &keyID); err != nil {
			return fmt.Errorf("key at index %d missing key ID: %w", i, err)
		}

		if keyID == "" {
			return fmt.Errorf("key at index %d has empty key ID", i)
		}

		// Validate key type (should be RSA for this implementation)
		if key.KeyType() != jwa.RSA() {
			return fmt.Errorf("unsupported key type: %s", key.KeyType())
		}
	}

	return nil
}

// GetDatasetInfo returns information about a dataset without deserializing the full JWK set
func GetDatasetInfo(dataset *JWKDataset) (*JWKMetadata, error) {
	if dataset == nil {
		return nil, errors.New("dataset cannot be nil")
	}

	return dataset.Metadata, nil
}

// ValidateDatasetIntegrity checks if a dataset is valid without loading it into the manager
func ValidateDatasetIntegrity(dataset *JWKDataset) error {
	if dataset == nil {
		return errors.New("dataset cannot be nil")
	}

	if dataset.ID == "" {
		return errors.New("dataset ID is required")
	}

	if len(dataset.KeySetData) == 0 {
		return errors.New("key set data is empty")
	}

	if dataset.Checksum == "" {
		return errors.New("checksum is required")
	}

	// Create a temporary manager to verify checksum
	tempManager := &jwkManager{}
	if err := tempManager.verifyChecksum(dataset.KeySetData, dataset.Checksum); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Check expiration
	if dataset.ExpiresAt != nil && time.Now().After(*dataset.ExpiresAt) {
		return errors.New("dataset has expired")
	}

	// Validate that the data can be unmarshaled
	var jwkSet jwk.Set
	if err := json.Unmarshal(dataset.KeySetData, &jwkSet); err != nil {
		return fmt.Errorf("invalid JWK set data: %w", err)
	}

	return nil
}
