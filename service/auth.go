package service

import (
	"crypto/rsa"
	"encoding/json"

	"github.com/sushan531/jwkauth/internal/manager"
	"github.com/sushan531/jwkauth/model"
)

type AuthService interface {
	GenerateJwt(user *model.User, deviceType string) (string, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (*model.User, error)
}

type authService struct {
	jwtManager manager.JwtManager
	jwkManager manager.JwkManager
}

func NewAuthService(jwtManager manager.JwtManager, jwkManager manager.JwkManager) AuthService {
	return &authService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
	}
}

func (a authService) GenerateJwt(user *model.User, deviceType string) (string, error) {
	// Set the user ID in the JWK manager if it supports it
	if setter, ok := a.jwkManager.(interface{ SetUserId(int) }); ok {
		setter.SetUserId(user.Id)
	}

	var userAsMap = user.ToMap()
	return a.jwtManager.GenerateToken(userAsMap, deviceType)
}

func (a authService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

func (a authService) VerifyToken(token string) (*model.User, error) {
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

	// Set the user ID in the JWK manager if it supports it
	if setter, ok := a.jwkManager.(interface{ SetUserId(int) }); ok {
		setter.SetUserId(user.Id)
	}

	return user, nil
}
