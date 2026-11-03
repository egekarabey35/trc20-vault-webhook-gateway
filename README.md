# TRC-20 Webhook Gateway — Security Engineering Demonstration

A Go-based **webhook ingestion prototype** for TRC-20-style transaction notifications, using HMAC-SHA256 request authentication, Redis duplicate suppression and a file-based secret compatible with Vault Agent injection.

> **Not a payment processor:** The repository does **not** verify TRON blockchain confirmations, transfer funds or credit a real ledger. `processFintechTransfer` is currently a placeholder that returns success. Use this repository only as a security-engineering demonstration until a real settlement/reconciliation layer is implemented and reviewed.

## Implemented components

| Component | Source | What it does |
|---|---|---|
| HTTP gateway | [`src/cmd/server/main.go`](src/cmd/server/main.go) | `POST /webhook/trc20`, `GET /healthz`, `GET /readyz`; body limit 1 MiB |
| Signature verification | [`src/internal/auth/verifier.go`](src/internal/auth/verifier.go) | HMAC-SHA256 comparison using `subtle.ConstantTimeCompare` |
| Duplicate suppression | [`src/cmd/server/main.go`](src/cmd/server/main.go) | Redis `SETNX` on `tx:<tx_hash>`; 5-minute PENDING lock, then 24-hour PROCESSED marker |
| Kubernetes configuration | [`k8s/base/`](k8s/base/) | Restricted container security context, probes, NetworkPolicy and Vault Agent injection annotations |
| Vault ACL example | [`vault/policies/webhook-gateway-policy.hcl`](vault/policies/webhook-gateway-policy.hcl) | Intended read-only scope for the webhook secret |
| Tests | [`src/cmd/server/main_test.go`](src/cmd/server/main_test.go), [`src/internal/auth/verifier_test.go`](src/internal/auth/verifier_test.go) | Concurrent replay scenario and signature verification tests |

## Architecture

1. A caller submits the *exact raw JSON request body* to `POST /webhook/trc20`, with an `X-TRC20-Signature` header containing the lowercase hexadecimal HMAC-SHA256 of that body.
2. The server reads its current shared secret from a file (`VAULT_SECRET_FILE`, default `/vault/secrets/webhook-secret`). A periodic poll supports rotation.
3. The signature is checked before decoding the JSON payload. A Redis lock keyed by transaction hash rejects competing/duplicate requests.
4. The demonstration handler calls the placeholder `processFintechTransfer`, then records the hash as PROCESSED. **A 200 OK does not mean an on-chain payment was verified.**

Expected JSON fields include `tx_hash`, `amount`, `token`, `to_address`, and `timestamp`. The amount uses `json.Number` rather than a floating-point value.

## Local development / tests

Requirements: **Go 1.22+** and a Redis server.

```bash
go test ./...
```

To run the Go server outside Kubernetes, provide a secret file with appropriate local file permissions and point the app to a Redis instance:

```bash
export REDIS_ADDR=localhost:6379
export VAULT_SECRET_FILE=/absolute/path/to/local/webhook-secret
export PORT=8080
go run ./src/cmd/server
```

`GET /healthz` responds when the process is reachable; **`GET /readyz` only succeeds when Redis is reachable and a nonempty secret has been loaded**.

The included [`docker-compose.yml`](docker-compose.yml) starts development Vault and Redis containers but does **not** provision the required Vault secret, Vault Agent injector or `VAULT_SECRET_FILE` mount for the gateway. Accordingly, `docker compose up` alone is **not a fully working end-to-end secret-injection demonstration**. The sample Compose file includes a hardcoded development-only Vault token and exposed ports; never deploy it to the internet or reuse those credentials.

## Known limitations and future work

- **No on-chain verification:** The gateway accepts signed notifications but does not independently query a TRON node to verify finality, token contract or receiver.
- **No settlement implementation:** `processFintechTransfer` is a no-op placeholder; a real application would need an idempotent ledger integration.
- **Redis expiration / crash recovery:** The PENDING lock expires after five minutes; interrupted transactions and late replays need durable reconciliation and stronger lifecycle guarantees.
- **Partial input validation:** The current handler does not perform full semantic validation of hash, address, token, amount or timestamp. The `tx_hash` is trusted as supplied after signature verification.
- **Deployment prerequisites:** Kubernetes manifests include a sample pinned image digest, Vault role and external Redis/Vault assumptions. These must be replaced/configured and tested in an actual cluster.
- **Observability & review:** Add structured redacted logging, metrics, threat modeling, integration tests, CI and independent security review before any production use.

This project demonstrates layered webhook controls and explicit analysis of where those controls **are not yet sufficient** for production financial services.
