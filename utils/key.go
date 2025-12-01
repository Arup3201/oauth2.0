package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func GenerateRandomKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random key generate error: %w", err)
	}

	hasher := sha256.New()
	if _, err := hasher.Write(b); err != nil {
		return "", fmt.Errorf("random key hash error: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
