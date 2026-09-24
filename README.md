
Enterprise-grade, Zero-Trust TRC-20 payment webhook gateway built with Go, HashiCorp Vault, Redis, and Kubernetes.

## Security Features
- Dynamic Secret Management with HashiCorp Vault
- Timing Attack Mitigation via Constant-Time HMAC-SHA256
- Idempotent Transaction Processing & Redis Replay Shield
- Zero-Trust Kubernetes Hardening & Strict NetworkPolicies

## Tech Stack

---

## Known Limitations & Production Roadmap

- **Idempotency Window vs. Reconciliation:**
  The `PENDING` state lock TTL is configured to **5 minutes** to mitigate double-spend risks during slow downstream ledger executions. While this reduces the practical race condition window significantly, distributed systems edge-cases (e.g., container SIGKILL during execution followed by an upstream retry after 5 minutes) require architectural remediation. A scheduled background **Reconciliation Worker** is planned to scan and resolve stuck pending transactions asynchronously.
- **On-Chain Confirmation:**
  The gateway currently acts as a high-throughput webhook ingestion layer with HMAC timing-attack mitigation. End-to-end cryptographic settlement requires full-node RPC verification (e.g., TronGrid query) before final balance allocation.
