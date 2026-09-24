package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/redis/go-redis/v9"

	"trc20-vault-webhook-gateway/src/internal/auth"
)

type TRC20Payload struct {
	TxHash      string `json:"tx_hash"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Amount      string `json:"amount"`
	TokenSymbol string `json:"token_symbol"`
	Timestamp   int64  `json:"timestamp"`
}

func getVaultSecret(vaultAddr, token, path string) (string, error) {
	config := vault.DefaultConfig()
	config.Address = vaultAddr
	client, err := vault.NewClient(config)
	if err != nil {
		return "", err
	}
	client.SetToken(token)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", http.ErrNoCookie
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", http.ErrNoCookie
	}

	return data["hmac_secret"].(string), nil
}

func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		vaultToken = "root-dev-token"
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}

	log.Println("[INFO] Vault'tan dinamik HMAC secret okunuyor...")
	hmacSecret, err := getVaultSecret(vaultAddr, vaultToken, "secret/data/trc20/gateway")
	if err != nil {
		log.Fatalf("[FATAL] Vault secret okunamadı: %v", err)
	}
	log.Println("[SUCCESS] Vault secret başarıyla alındı.")

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[FATAL] Redis bağlantısı kurulamadı: %v", err)
	}

	verifier := auth.NewVerifier(hmacSecret, rdb, 24*time.Hour)

	http.HandleFunc("/api/v1/webhook/trc20", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		sigHeader := r.Header.Get("X-Signature-SHA256")
		if sigHeader == "" {
			http.Error(w, "Missing Signature Header", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// 1. HMAC Doğrulaması
		if err := verifier.VerifySignature(body, sigHeader); err != nil {
			log.Printf("[SECURITY] Geçersiz imza: %v", err)
			http.Error(w, "Unauthorized: Signature mismatch", http.StatusUnauthorized)
			return
		}

		var payload TRC20Payload
		if err := json.Unmarshal(body, &payload); err != nil || payload.TxHash == "" {
			http.Error(w, "Invalid JSON payload or missing tx_hash", http.StatusBadRequest)
			return
		}

		// 2. Replay Kalkanı (Redis Atomik Kontrol)
		if err := verifier.PreventReplay(r.Context(), payload.TxHash); err != nil {
			if errorsIs(err, auth.ErrReplayDetected) {
				log.Printf("[SECURITY] Replay atağı engellendi! TxHash: %s", payload.TxHash)
				http.Error(w, "Conflict: Replay attack detected", http.StatusConflict)
				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		log.Printf("[ACCEPTED] Geçerli TRC-20 Transfer: Hash=%s, Amount=%s %s, To=%s",
			payload.TxHash, payload.Amount, payload.TokenSymbol, payload.ToAddress)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"accepted","message":"Webhook processed securely"}`))
	})

	log.Println("[INFO] TRC-20 Webhook Gateway :8080 portunda dinliyor...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("[FATAL] Sunucu hatası: %v", err)
	}
}

func errorsIs(err, target error) bool {
	return err == target
}
