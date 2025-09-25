package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JwkManager interface {
	InitializeJwkSet(keyPrefix string) error
	LoadJwkSetFromJSON(jwkSetJSON string) error
	GetJwkSetAsJSON() (string, error)
	GetAnyPrivateKeyWithKeyId(keyPrefix string) (*rsa.PrivateKey, string, error)
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	AddKeyToSet(keyPrefix string) error
	HasKeyForPrefix(keyPrefix string) bool
}

type jwkManager struct {
	jwkSet jwk.Set
}

func NewJwkManager() JwkManager {
	return &jwkManager{}
}

func (j *jwkManager) InitializeJwkSet(keyPrefix string) error {
	// Generate a new key set with a single key
	set := jwk.NewSet()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := set.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to set: %w", err)
	}

	j.jwkSet = set
	return nil
}

func (j *jwkManager) LoadJwkSetFromJSON(jwkSetJSON string) error {
	if jwkSetJSON == "" {
		return errors.New("empty JWK set JSON")
	}

	set, err := jwk.ParseString(jwkSetJSON)
	if err != nil {
		return fmt.Errorf("failed to parse JWK set: %w", err)
	}

	j.jwkSet = set
	return nil
}

func (j *jwkManager) GetJwkSetAsJSON() (string, error) {
	if j.jwkSet == nil {
		return "", errors.New("JWK set not initialized")
	}

	jwkSetJSON, err := json.Marshal(j.jwkSet)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK set: %w", err)
	}

	return string(jwkSetJSON), nil
}

func (j *jwkManager) AddKeyToSet(keyPrefix string) error {
	if j.jwkSet == nil {
		return errors.New("JWK set not initialized")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into JWK: %w", err)
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := j.jwkSet.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to set: %w", err)
	}

	return nil
}

func (j *jwkManager) HasKeyForPrefix(keyPrefix string) bool {
	if j.jwkSet == nil {
		return false
	}

	keyID := fmt.Sprintf("key-%s", keyPrefix)
	_, found := j.jwkSet.LookupKeyID(keyID)
	return found
}

// ... existing code ...
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
