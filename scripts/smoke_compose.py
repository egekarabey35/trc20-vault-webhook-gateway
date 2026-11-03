#!/usr/bin/env python3
"""Local-only HTTP smoke test for the demo gateway and Redis, run in CI.

This does NOT interact with TRON or process a financial transaction.
"""
import hashlib
import hmac
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = "http://127.0.0.1:8080"
KEY = b"test-only-ci-secret"


def request(path, body=None, signature=None):
    headers = {}
    method = "GET"
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["X-TRC20-Signature"] = signature or ""
        method = "POST"
    req = Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=3) as res:
            return res.status, res.read().decode("utf-8")
    except HTTPError as err:
        return err.code, err.read().decode("utf-8")


def main():
    for _ in range(45):
        try:
            status, _ = request("/readyz")
            if status == 200:
                break
        except (OSError, URLError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Gateway did not become ready in 45 seconds")

    payload = json.dumps({
        "tx_hash": "a" * 64,
        "amount":  "12.5000",
        "token": "USDT",
        "to_address": "T" + "A" * 33,
        "timestamp": int(time.time()),
    }, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(KEY, payload, hashlib.sha256).hexdigest()

    status, _ = request("/webhook/trc20", payload, "bad-signature")
    assert status == 401, f"Invalid signature was not rejected: {status}"

    status, body = request("/webhook/trc20", payload, signature)
    assert status == 200 and "validated_demo" in body, (status, body)

    status, _ = request("/webhook/trc20", payload, signature)
    assert status == 409, f"Replay was not rejected: {status}"

    invalid = json.dumps({
        "tx_hash": "invalid",
        "amount": "0",
        "token": "USDT",
        "to_address": "wrong",
        "timestamp": int(time.time())
    }, separators=(",", ":")).encode("utf-8")
    status, _ = request("/webhook/trc20", invalid, hmac.new(KEY, invalid, hashlib.sha256).hexdigest())
    assert status == 400, f"Signed but invalid fields were accepted: {status}"
    print("PASS: readiness, invalid HMAC, validated demo, replay conflict, signed invalid fields")


if __name__ == "__main__":
    main()
