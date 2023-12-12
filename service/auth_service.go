package service

import (
	"context"

	"github.com/BerryTracer/auth-service/model"
	"github.com/BerryTracer/common-service/crypto"
	userservice "github.com/BerryTracer/user-service/grpc/proto"
)

type AuthService interface {
	SignUp(ctx context.Context, email string, username string, password string) (*model.Token, error)
	SignIn(ctx context.Context, email string, password string) (*model.Token, error)
	VerifyToken(ctx context.Context, tokenStr string) (bool, map[string]interface{}, error)
	RefreshToken(ctx context.Context, tokenStr string) (*model.Token, error)
}

type AuthServiceImpl struct {
	UserService    userservice.UserServiceClient
	TokenService   TokenService
	PasswordHasher crypto.PasswordHasher
}

// NewAuthServiceImpl creates a new AuthServiceImpl.
func NewAuthServiceImpl(userService userservice.UserServiceClient, tokenService TokenService, passwordHasher crypto.PasswordHasher) *AuthServiceImpl {
	return &AuthServiceImpl{
		UserService:    userService,
		TokenService:   tokenService,
		PasswordHasher: passwordHasher,
	}
}

// SignUp implements AuthService.
func (a *AuthServiceImpl) SignUp(ctx context.Context, email string, username string, password string) (*model.Token, error) {
	user, err := a.UserService.CreateUser(ctx, &userservice.CreateUserRequest{
		Email:    email,
		Username: username,
		Password: password,
	})

	if err != nil {
		return nil, err
	}

	userID := user.GetId()

	accessToken, err := a.TokenService.GenerateAccessToken(ctx, userID, nil)

	if err != nil {
		return nil, err
	}

	refreshToken, err := a.TokenService.GenerateRefreshToken(ctx, userID)

	if err != nil {
		return nil, err
	}

	return &model.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// SignIn implements AuthService.
func (a *AuthServiceImpl) SignIn(ctx context.Context, email string, password string) (*model.Token, error) {
	user, err := a.UserService.GetUserByEmail(ctx, &userservice.GetUserByEmailRequest{
		Email: email,
	})

	if err != nil {
		return nil, err
	}

	userID := user.GetId()
	hashedPassword := user.GetHashedPassword()

	err = a.PasswordHasher.ComparePassword(password, hashedPassword)

	if err != nil {
		return nil, err
	}

	accessToken, err := a.TokenService.GenerateAccessToken(ctx, userID, nil)

	if err != nil {
		return nil, err
	}

	refreshToken, err := a.TokenService.GenerateRefreshToken(ctx, userID)

	if err != nil {
		return nil, err
	}

	return &model.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// VerifyToken implements AuthService.
func (a *AuthServiceImpl) VerifyToken(ctx context.Context, tokenStr string) (bool, map[string]interface{}, error) {
	return a.TokenService.ValidateToken(ctx, tokenStr)
}

// RefreshToken implements AuthService.
func (a *AuthServiceImpl) RefreshToken(ctx context.Context, tokenStr string) (*model.Token, error) {
	return a.TokenService.RefreshToken(ctx, tokenStr)
}
