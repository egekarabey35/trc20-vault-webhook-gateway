package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidSignature = errors.New("invalid webhook signature")
	ErrReplayDetected   = errors.New("replay attack detected: transaction already processed")
)

type Verifier struct {
	hmacSecret []byte
	redisCli   *redis.Client
	ttl        time.Duration
}

func NewVerifier(secret string, redisCli *redis.Client, replayTTL time.Duration) *Verifier {
	return &Verifier{
		hmacSecret: []byte(secret),
		redisCli:   redisCli,
		ttl:        replayTTL,
	}
}

// VerifySignature, timing attack'leri önlemek için constant-time karşılaştırma kullanır.
func (v *Verifier) VerifySignature(payload []byte, signatureHex string) error {
	mac := hmac.New(sha256.New, v.hmacSecret)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	actualMAC, err := hex.DecodeString(signatureHex)
	if err != nil {
		return ErrInvalidSignature
	}

	if subtle.ConstantTimeCompare(expectedMAC, actualMAC) != 1 {
		return ErrInvalidSignature
	}
	return nil
}

// PreventReplay, Redis'e atomik SETNX (Set if Not Exists) atarak çift harcamayı engeller.
func (v *Verifier) PreventReplay(ctx context.Context, txHash string) error {
	key := "tx_seen:" + txHash
	success, err := v.redisCli.SetNX(ctx, key, "processed", v.ttl).Result()
	if err != nil {
		return err
	}
	if !success {
		return ErrReplayDetected
	}
	return nil
}
