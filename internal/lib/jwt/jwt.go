package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/muerewa/sso/internal/domain/models"
	"time"
)

type CustomClaims struct {
	UID       int64  `json:"uid"`
	Email     string `json:"email"`
	TokenType string `json:"type"` // "access" or "refresh"
	AppID     int    `json:"app_id"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
	ErrTokenRevoked = errors.New("token revoked")
	ErrWrongType    = errors.New("token is not a refresh token")
)

func RenewAccessToken(oldRefresh string, user models.User, app models.App, refTokenTTL time.Duration) (string, error) {
	parsed, err := jwt.ParseWithClaims(
		oldRefresh,
		&CustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, ErrInvalidToken
			}
			return []byte(app.Secret), nil
		},
	)
	if err != nil {
		return "", ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*CustomClaims)
	if !ok || !parsed.Valid {
		return "", ErrInvalidToken
	}

	if claims.TokenType != "refresh" {
		return "", ErrWrongType
	}

	if claims.ExpiresAt.Time.Before(time.Now().UTC()) {
		return "", ErrTokenExpired
	}

	refreshClaims := CustomClaims{
		UID:       user.ID,
		Email:     user.Email,
		TokenType: "access",
		AppID:     app.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(refTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ID:        uuid.NewString(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refresh, err := refreshToken.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return refresh, nil
}

func GenerateTokenPair(user models.User, app models.App, tokenTTL, refTokenTTL time.Duration) (access, refresh string, err error) {

	accessClaims := CustomClaims{
		UID:       user.ID,
		Email:     user.Email,
		AppID:     app.ID,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ID:        uuid.NewString(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	access, err = accessToken.SignedString([]byte(app.Secret))
	if err != nil {
		return "", "", err
	}

	refreshClaims := CustomClaims{
		UID:       user.ID,
		Email:     user.Email,
		TokenType: "refresh",
		AppID:     app.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(refTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ID:        uuid.NewString(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refresh, err = refreshToken.SignedString([]byte(app.Secret))
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func DecodeTokenWithVerification(tokenString, secretKey string) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}
