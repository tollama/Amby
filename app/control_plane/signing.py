from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_payload(payload: dict[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(payload: dict[str, Any], key: str, signature: str) -> bool:
    expected = sign_payload(payload, key)
    return hmac.compare_digest(expected, signature)

