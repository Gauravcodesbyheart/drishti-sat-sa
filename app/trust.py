"""Offline evidence trust: SHA3-256 hash chain + local HMAC seal.

ML-DSA-65 (FIPS 204) is the production signing algorithm for NCIIPC air-gap
deployments. This prototype seals every finding and audit row with SHA3-256
and HMAC so the chain is verifiable without a PQC library. Swap `seal()` for
ML-DSA-65 at deployment time — the ledger schema does not change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "offline_seal.key")


def _key() -> bytes:
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(os.urandom(32))
    with open(KEY_PATH, "rb") as f:
        return f.read()


def sha3(payload: Any) -> str:
    if not isinstance(payload, (bytes, bytearray)):
        payload = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha3_256(payload).hexdigest()


def seal(payload: Any, prev_hash: str = "GENESIS") -> dict:
    body_hash = sha3(payload)
    chain = sha3(prev_hash + body_hash)
    sig = hmac.new(_key(), chain.encode("utf-8"), hashlib.sha3_256).hexdigest()
    return {
        "sha3_256": body_hash,
        "prev_hash": prev_hash,
        "chain_hash": chain,
        "seal": sig,
        "alg": "HMAC-SHA3-256 (ML-DSA-65 interface)",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
    }


def verify(payload: Any, record: dict) -> bool:
    body_hash = sha3(payload)
    if body_hash != record.get("sha3_256"):
        return False
    chain = sha3(record.get("prev_hash", "GENESIS") + body_hash)
    if chain != record.get("chain_hash"):
        return False
    expect = hmac.new(_key(), chain.encode("utf-8"), hashlib.sha3_256).hexdigest()
    return hmac.compare_digest(expect, record.get("seal", ""))
