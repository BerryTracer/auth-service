package service

import (
	"context"
	"errors"
	"time"

	"github.com/BerryTracer/auth-service/model"
	"github.com/golang-jwt/jwt/v5"
)

type TokenService interface {
	GenerateAccessToken(ctx context.Context, userID string, additionalClaims map[string]interface{}) (string, error)
	GenerateRefreshToken(ctx context.Context, userID string) (string, error)
	ValidateToken(ctx context.Context, tokenStr string) (bool, map[string]interface{}, error)
	RefreshToken(ctx context.Context, tokenStr string) (*model.Token, error)
}

const (
	AccessTokenDuration  = 15 * 60          // 15 minutes
	RefreshTokenDuration = 7 * 24 * 60 * 60 // 7 days
)

type TokenServiceImpl struct {
	SigningKey string
}

func (s *TokenServiceImpl) GenerateAccessToken(ctx context.Context, userID string, additionalClaims map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(AccessTokenDuration).Unix(),
	}

	if additionalClaims != nil {
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.SigningKey))
}

func (s *TokenServiceImpl) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(RefreshTokenDuration).Unix(),
		"rt":      true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.SigningKey))
}

// ValidateToken implements TokenService.
func (t *TokenServiceImpl) ValidateToken(ctx context.Context, tokenStr string) (bool, map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.SigningKey), nil
	})

	if err != nil {
		return false, nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, claims, nil
	}

	return false, nil, nil
}

// RefreshToken implements TokenService.
func (t *TokenServiceImpl) RefreshToken(ctx context.Context, tokenStr string) (*model.Token, error) {
	isValid, claims, err := t.ValidateToken(ctx, tokenStr)

	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, errors.New("invalid token")
	}

	userID := claims["user_id"].(string)

	accessToken, err := t.GenerateAccessToken(ctx, userID, nil)

	if err != nil {
		return nil, err
	}

	refreshToken, err := t.GenerateRefreshToken(ctx, userID)

	if err != nil {
		return nil, err
	}

	return &model.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func NewTokenService(signingKey string) *TokenServiceImpl {
	return &TokenServiceImpl{SigningKey: signingKey}
}

// Ensure that the TokenServiceImpl implements the TokenService interface
var _ TokenService = (*TokenServiceImpl)(nil)
