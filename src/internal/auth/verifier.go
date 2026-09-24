package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid webhook signature")

// VerifyHMAC timing attack önlemek için constant-time karşılaştırma yapar
func VerifyHMAC(payload []byte, signatureHex string, secret string) error {
	expectedMAC := hex.EncodeToString(ComputeHMAC(payload, secret))

	if subtle.ConstantTimeCompare([]byte(expectedMAC), []byte(signatureHex)) != 1 {
		return ErrInvalidSignature
	}
	return nil
}

func ComputeHMAC(payload []byte, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return mac.Sum(nil)
}
