package main

import (
    "encoding/json"
    "strings"
    "testing"
    "time"
)

func TestValidateSignedWebhookFields(t *testing.T) {
    now := time.Now()
    base := WebhookPayload{
        TxHash: strings.Repeat("a", 64),
        Amount: json.Number("123.4500"),
        Token: "USDT",
        ToAddress: "T" + strings.Repeat("A", 33),
        Timestamp: now.Unix(),
    }
    tests := []struct {
        name string
        modify func(*WebhookPayload)
        wantError bool
    }{
        {"valid", func(*WebhookPayload){}, false},
        {"invalid hash", func(p *WebhookPayload){p.TxHash = "../bad"}, true},
        {"invalid address", func(p *WebhookPayload){p.ToAddress = "TRX123"}, true},
        {"empty token", func(p *WebhookPayload){p.Token = ""}, true},
        {"zero amount", func(p *WebhookPayload){p.Amount = json.Number("0")}, true},
        {"negative amount", func(p *WebhookPayload){p.Amount = json.Number("-1")}, true},
        {"scientific notation", func(p *WebhookPayload){p.Amount = json.Number("1e6")}, true},
        {"amount too precise", func(p *WebhookPayload){p.Amount = json.Number("0."+strings.Repeat("1",19))}, true},
        {"stale timestamp", func(p *WebhookPayload){p.Timestamp = now.Add(-6*time.Minute).Unix()}, true},
        {"future timestamp", func(p *WebhookPayload){p.Timestamp = now.Add(3*time.Minute).Unix()}, true},
        {"missing timestamp", func(p *WebhookPayload){p.Timestamp = 0}, true},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T){
            p := base
            tc.modify(&p)
            err := validatePayload(p, now)
            if (err != nil) != tc.wantError {t.Fatalf("validatePayload() err=%v, wantError=%v", err, tc.wantError)}
        })
    }
}
