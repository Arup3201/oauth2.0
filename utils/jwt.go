package utils

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ENV_TOKEN_SECRET = "TOKEN_SECRET"
)

func GetJWTString(claims jwt.MapClaims) (string, error) {
	jwtPayload := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signSecret := os.Getenv(ENV_TOKEN_SECRET)
	if signSecret == "" {
		return "", fmt.Errorf("[ERROR] environment variable '%s' is missing", ENV_TOKEN_SECRET)
	}
	jwtString, err := jwtPayload.SignedString([]byte(signSecret))
	if err != nil {
		return "", err
	}

	return jwtString, nil
}

func VerifyJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		signSecret := os.Getenv(ENV_TOKEN_SECRET)
		return []byte(signSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return token, nil
}
