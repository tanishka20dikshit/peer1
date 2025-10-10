
"""Small helpers (timestamps, uuid, replay cache)."""
from __future__ import annotations
import time, uuid, hashlib
from typing import Dict

def now_ms() -> int:
    return int(time.time()*1000)

def uuid4() -> str:
    return str(uuid.uuid4())

class ReplayCache:
    """Tiny duplicate-suppression cache (for anti-replay / anti-loop)."""
    def __init__(self, max_items: int = 2048, ttl_sec: int = 60):
        self.max_items = max_items
        self.ttl_sec = ttl_sec
        self._store: Dict[bytes, float] = {}

    def seen(self, *fields: bytes) -> bool:
        now = time.time()
        digest = hashlib.sha256(b"||".join(fields)).digest()[:16]
        # evict expired
        expired = [k for k,t in self._store.items() if t < now]
        for k in expired: self._store.pop(k, None)
        if digest in self._store: return True
        self._store[digest] = now + self.ttl_sec
        # trim
        if len(self._store) > self.max_items:
            for k in list(self._store.keys())[:len(self._store)-self.max_items]:
                self._store.pop(k, None)
        return False
