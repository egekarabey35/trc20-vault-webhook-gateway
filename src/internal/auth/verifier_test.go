package auth

import (
	"encoding/hex"
	"testing"
)

func TestVerifyHMAC(t *testing.T) {
	secret := "super_secret_vault_key_123!"
	payload := []byte(`{"tx_hash":"0x9f8382abc","amount":1500.50,"token":"USDT"}`)

	// Geçerli imzayı hesapla
	validMAC := ComputeHMAC(payload, secret)
	validSignatureHex := hex.EncodeToString(validMAC)

	tests := []struct {
		name      string
		signature string
		secret    string
		expectErr error
	}{
		{"Gecerli Imza", validSignatureHex, secret, nil},
		{"Gecersiz Imza (Rastgele)", "deadbeef1234567890abcdef", secret, ErrInvalidSignature},
		{"Bos Imza", "", secret, ErrInvalidSignature},
		{"Yanlis Secret", validSignatureHex, "wrong_secret_key", ErrInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMAC(payload, tt.signature, tt.secret)
			if err != tt.expectErr {
				t.Errorf("beklenen %v, alinan %v", tt.expectErr, err)
			}
		})
	}
}
