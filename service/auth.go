package service

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"jwk-single-device-login/internal/database"
	"jwk-single-device-login/internal/manager"
	"jwk-single-device-login/model"
)

type AuthService interface {
	GenerateJwt(user *model.User, deviceType string) (string, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (*model.User, error)
}

type authService struct {
	jwtManager manager.JwtManager
	jwkManager manager.JwkManager
	db         *database.DB
}

func NewAuthService(jwtManager manager.JwtManager, jwkManager manager.JwkManager) AuthService {
	db, err := database.NewDB()
	if err != nil {
		// Log the error but continue without database support
		fmt.Printf("Warning: Failed to initialize database: %v\n", err)
		return &authService{
			jwtManager: jwtManager,
			jwkManager: jwkManager,
		}
	}

	return &authService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
		db:         db,
	}
}

func (a *authService) GenerateJwt(user *model.User, deviceType string) (string, error) {
	// Load or initialize JWK set for this user and device type
	if err := a.loadOrInitializeJwkSet(user.Id, deviceType); err != nil {
		return "", fmt.Errorf("failed to load/initialize JWK set: %w", err)
	}

	var userAsMap = user.ToMap()
	return a.jwtManager.GenerateToken(userAsMap, deviceType)
}

func (a *authService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

func (a *authService) VerifyToken(token string) (*model.User, error) {
	claimsInMap, errVerifyingSignature := a.jwtManager.VerifyTokenSignatureAndGetClaims(token)
	if errVerifyingSignature != nil {
		return nil, errVerifyingSignature
	}

	var user *model.User
	userDataInBytes, errMarshallingData := json.Marshal(claimsInMap["claim"])
	if errMarshallingData != nil {
		return nil, errMarshallingData
	}

	errUnmarshallingData := json.Unmarshal(userDataInBytes, &user)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}

	return user, nil
}

// loadOrInitializeJwkSet handles the database operations for JWK sets
func (a *authService) loadOrInitializeJwkSet(userID int, deviceType string) error {
	// If no database, just initialize a new set
	if a.db == nil {
		return a.jwkManager.InitializeJwkSet(deviceType)
	}

	// Try to load existing JWK set from database
	jwkSetJSON, err := a.db.GetJWKSet(userID)
	if err != nil {
		return fmt.Errorf("failed to get JWK set from database: %w", err)
	}

	if jwkSetJSON != "" {
		// Load existing JWK set
		if err := a.jwkManager.LoadJwkSetFromJSON(jwkSetJSON); err != nil {
			// If loading fails, initialize a new set
			if err := a.jwkManager.InitializeJwkSet(deviceType); err != nil {
				return err
			}
		} else {
			// Check if we need to add a key for this device type
			if !a.jwkManager.HasKeyForPrefix(deviceType) {
				if err := a.jwkManager.AddKeyToSet(deviceType); err != nil {
					return err
				}
				// Save the updated set
				return a.saveJwkSet(userID)
			}
			return nil
		}
	} else {
		// No existing set, create new one
		if err := a.jwkManager.InitializeJwkSet(deviceType); err != nil {
			return err
		}
	}

	// Save the new/updated set to database
	return a.saveJwkSet(userID)
}

// saveJwkSet saves the current JWK set to the database
func (a *authService) saveJwkSet(userID int) error {
	if a.db == nil {
		return nil // No database available
	}

	jwkSetJSON, err := a.jwkManager.GetJwkSetAsJSON()
	if err != nil {
		return fmt.Errorf("failed to get JWK set as JSON: %w", err)
	}

	if err := a.db.SaveJWKSet(userID, jwkSetJSON); err != nil {
		return fmt.Errorf("failed to save JWK set to database: %w", err)
	}

	return nil
}
