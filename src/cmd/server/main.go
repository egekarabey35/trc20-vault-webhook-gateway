package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"trc20-vault-webhook-gateway/src/internal/auth"
)

type WebhookPayload struct {
	TxHash    string      `json:"tx_hash"`
	// CRITICAL FIX: Financial systems must NEVER use float64. Using json.Number strictly preserves precision.
	Amount    json.Number `json:"amount"`
	Token     string      `json:"token"`
	ToAddress string      `json:"to_address"`
	Timestamp int64       `json:"timestamp"`
}

type GatewayServer struct {
	redisClient *redis.Client
	secretMu    sync.RWMutex
	vaultSecret string
	secretPath  string
}

func NewGatewayServer(redisAddr, secretPath string) *GatewayServer {
	srv := &GatewayServer{
		redisClient: redis.NewClient(&redis.Options{
			Addr: redisAddr,
		}),
		secretPath: secretPath,
	}
	if err := srv.loadSecret(); err != nil {
		log.Printf("[WARN] Vault Agent secret dosyası henüz hazır değil (%v), fallback/beklemede.", err)
	}
	go srv.watchSecretFile()
	return srv
}

func (s *GatewayServer) loadSecret() error {
	data, err := os.ReadFile(s.secretPath)
	if err != nil {
		return err
	}
	cleaned := strings.TrimSpace(string(data))
	if cleaned == "" {
		return errors.New("secret file is empty")
	}
	s.secretMu.Lock()
	s.vaultSecret = cleaned
	s.secretMu.Unlock()
	log.Println("[SECURITY] Dynamic webhook secret güncellendi / yüklendi.")
	return nil
}

func (s *GatewayServer) watchSecretFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := s.loadSecret(); err != nil {
			continue
		}
	}
}

func (s *GatewayServer) getSecret() string {
	s.secretMu.RLock()
	defer s.secretMu.RUnlock()
	return s.vaultSecret
}

func (s *GatewayServer) healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (s *GatewayServer) readyzHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.redisClient.Ping(ctx).Err(); err != nil {
		http.Error(w, `{"status":"not_ready","reason":"redis_unreachable"}`, http.StatusServiceUnavailable)
		return
	}
	if s.getSecret() == "" {
		http.Error(w, `{"status":"not_ready","reason":"secret_not_loaded"}`, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

func (s *GatewayServer) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	signature := r.Header.Get("X-TRC20-Signature")
	if signature == "" {
		log.Println("[SECURITY] Eksik imza basligi")
		http.Error(w, "Unauthorized: Missing Signature", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	activeSecret := s.getSecret()
	if activeSecret == "" {
		log.Println("[ERROR] Doğrulama secret'ı henüz hazır değil")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := auth.VerifyHMAC(body, signature, activeSecret); err != nil {
		log.Printf("[SECURITY] Geçersiz imza denemesi: %v", err)
		http.Error(w, "Unauthorized: Invalid Signature", http.StatusUnauthorized)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON Payload", http.StatusBadRequest)
		return
	}
	if err := validatePayload(payload, time.Now()); err != nil {
		log.Printf("[REJECTED] Invalid signed webhook fields: %v", err)
		http.Error(w, "Invalid Transaction Fields", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	
	key := "tx:" + payload.TxHash
	acquired, err := s.redisClient.SetNX(ctx, key, "PENDING", 5*time.Minute).Result()
	if err != nil {
		log.Printf("[ERROR] Redis bağlantı hatası: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !acquired {
		log.Printf("[SECURITY] Replay atağı veya mükerrer işlem engellendi! TxHash: %s", payload.TxHash)
		http.Error(w, "Conflict: Transaction already processing or processed", http.StatusConflict)
		return
	}

	err = processFintechTransfer(payload)
	if err != nil {
		log.Printf("[ERROR] Transfer işleme hatası: %v. Kilit serbest bırakılıyor.", err)
		// CRITICAL FIX: Use context.Background() for cleanup because original ctx might be deadline exceeded
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		if cleanupErr := s.redisClient.Del(cleanupCtx, key).Err(); cleanupErr != nil {
			log.Printf("[WARN] Failed to release pending transaction key: %v", cleanupErr)
		}
		http.Error(w, "Payment Processing Failed", http.StatusBadGateway)
		return
	}

	if err := s.redisClient.Set(ctx, key, "PROCESSED", 24*time.Hour).Err(); err != nil {
		log.Printf("[ERROR] Redis could not commit demo replay marker: %v", err)
		http.Error(w, "Replay State Unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("[VALIDATED_DEMO] Signed webhook validated and deduplicated: Hash=%s", payload.TxHash)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"validated_demo"}`))
}

func processFintechTransfer(p WebhookPayload) error {
	return nil
}

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}
	secretPath := os.Getenv("VAULT_SECRET_FILE")
	if secretPath == "" {
		secretPath = "/vault/secrets/webhook-secret"
	}

	server := NewGatewayServer(redisAddr, secretPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/trc20", server.webhookHandler)
	mux.HandleFunc("/healthz", server.healthzHandler)
	mux.HandleFunc("/readyz", server.readyzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
	}

	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("[INFO] Hardened TRC-20 Gateway :%s portunda dinliyor...", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Sunucu hatası: %v", err)
		}
	}()

	<-stopCtx.Done()
	log.Println("[INFO] SIGTERM sinyali alındı. Graceful shutdown başlatılıyor...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Graceful shutdown zorlandı: %v", err)
	}
	log.Println("[SUCCESS] Sunucu güvenli bir şekilde kapatıldı.")
}
