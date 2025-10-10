
"""Envelope helpers for canonical JSON & transport signatures (server↔server + server→user)."""
from __future__ import annotations
import json, hashlib
from typing import Dict, Any
from crypto import b64u, b64u_decode, sign_pss_sha256, verify_pss_sha256, load_public_spki_b64u

def canonical_json(obj: Dict[str, Any]) -> bytes:
    """Canonical JSON payload encoding: sorted keys, minimal separators, UTF-8 bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def transport_sign(priv, payload: Dict[str, Any]) -> str:
    """Sign canonical payload (dict) -> base64url signature string."""
    return b64u(sign_pss_sha256(priv, canonical_json(payload)))

def transport_verify(pub_spki_b64u: str, payload: Dict[str, Any], sig_b64u: str) -> bool:
    """Verify signature using pinned SPKI b64url public key."""
    pub = load_public_spki_b64u(pub_spki_b64u)
    return verify_pss_sha256(pub, b64u_decode(sig_b64u), canonical_json(payload))

def payload_hash16(payload: Dict[str, Any]) -> bytes:
    """Short hash for loop/replay cache: first 16 bytes of SHA-256 over canonical payload."""
    return hashlib.sha256(canonical_json(payload)).digest()[:16]
