package main

import (
    "encoding/hex"
    "errors"
    "math/big"
    "regexp"
    "strings"
    "time"
)

var (
    decimalAmount = regexp.MustCompile(`^[0-9]+(?:\.[0-9]{1,18})?$`)
    tokenName = regexp.MustCompile(`^[A-Z0-9_]{2,20}$`)
    base58Address = regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`)
)

// validatePayload checks signed webhook fields before reserving any Redis key.
// Address validation is only a format check: it does not verify a TRON Base58Check
// checksum, token contract, chain confirmation, or transaction settlement.
func validatePayload(p WebhookPayload, now time.Time) error {
    hash := strings.TrimPrefix(strings.ToLower(p.TxHash), "0x")
    if len(hash) != 64 {
        return errors.New("tx_hash must be a 64-character hexadecimal transaction identifier")
    }
    if _, err := hex.DecodeString(hash); err != nil {
        return errors.New("tx_hash is not hexadecimal")
    }

    if !tokenName.MatchString(p.Token) {
        return errors.New("token must be a 2-20 character uppercase identifier")
    }
    if !base58Address.MatchString(p.ToAddress) {
        return errors.New("to_address does not match a TRON Base58 address format")
    }

    amount := p.Amount.String()
    if !decimalAmount.MatchString(amount) {
        return errors.New("amount must be a positive decimal, with at most 18 decimal places")
    }
    rational, ok := new(big.Rat).SetString(amount)
    if !ok || rational.Sign() <= 0 {
        return errors.New("amount must be greater than zero")
    }

    if p.Timestamp <= 0 {
        return errors.New("timestamp must be supplied in Unix seconds")
    }
    eventTime := time.Unix(p.Timestamp, 0)
    if eventTime.Before(now.Add(-5*time.Minute)) || eventTime.After(now.Add(2*time.Minute)) {
        return errors.New("timestamp is outside the accepted 5-minute past/2-minute future window")
    }
    return nil
}
