package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"trc20-vault-webhook-gateway/src/internal/auth"
)

func TestConcurrentWebhookIdempotency(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Miniredis baslatilamadi: %v", err)
	}
	defer mr.Close()

	tmpFile, err := os.CreateTemp("", "webhook-secret")
	if err != nil {
		t.Fatalf("Temp file hatasi: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	secretKey := "test_secret_123!"
	tmpFile.WriteString(secretKey)
	tmpFile.Close()

	srv := NewGatewayServer(mr.Addr(), tmpFile.Name())
	time.Sleep(50 * time.Millisecond)

	payloadBytes := []byte(`{"tx_hash":"0xabc123","amount":100,"token":"USDT","to_address":"TRX123"}`)
	mac := auth.ComputeHMAC(payloadBytes, secretKey)
	signatureHex := hex.EncodeToString(mac)

	var successCount int32
	var conflictCount int32
	var wg sync.WaitGroup

	// 10 eşzamanlı istek gönderiliyor (Race condition simülasyonu)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodPost, "/webhook/trc20", bytes.NewBuffer(payloadBytes))
			req.Header.Set("X-TRC20-Signature", signatureHex)

			w := httptest.NewRecorder()
			srv.webhookHandler(w, req)

			if w.Code == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			} else if w.Code == http.StatusConflict {
				atomic.AddInt32(&conflictCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Errorf("Beklenen basarili islem (200 OK) sayisi 1, alinan: %d", successCount)
	}
	if conflictCount != 9 {
		t.Errorf("Beklenen Replay/Conflict (409) sayisi 9, alinan: %d", conflictCount)
	}
}
