"""Signed, single-use price quotes.

A quote pins the product, merchant, unit price, quantity and mandate with an HMAC. An
agent can carry it but cannot edit it: change one byte and verification fails. That is
what stops an injected instruction from swapping the payee or shaving the price.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from decimal import Decimal
from typing import Any

from .models import money


class QuoteError(ValueError):
    """The quote is malformed, forged, altered or expired."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise QuoteError("malformed quote") from exc


def _sign(key: str, body: bytes) -> str:
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def issue(
    key: str,
    *,
    mandate_id: str,
    product_id: str,
    merchant_id: str,
    unit_price: Decimal,
    currency: str,
    quantity: int,
    ttl_seconds: int,
    now: float | None = None,
) -> str:
    issued = int(time.time() if now is None else now)
    payload = {
        "qid": secrets.token_hex(8),
        "mid": mandate_id,
        "pid": product_id,
        "mer": merchant_id,
        "px": str(money(unit_price)),
        "cur": currency,
        "qty": int(quantity),
        "iat": issued,
        "exp": issued + int(ttl_seconds),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"{_b64(body)}.{_sign(key, body)}"


def verify(key: str, token: str, *, now: float | None = None) -> dict[str, Any]:
    if not isinstance(token, str) or token.count(".") != 1:
        raise QuoteError("malformed quote")
    body_b64, signature = token.split(".")
    body = _unb64(body_b64)
    expected = _sign(key, body).encode()
    if not hmac.compare_digest(expected, signature.encode("utf-8", "ignore")):
        raise QuoteError("signature mismatch (quote was altered or forged)")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise QuoteError("malformed quote") from exc
    current = time.time() if now is None else now
    if current > payload.get("exp", 0):
        raise QuoteError("quote expired")
    return payload


def tamper(token: str, **changes: Any) -> str:
    """Edit a quote's payload but keep the original signature. Used by the red-team harness."""
    body_b64, signature = token.split(".")
    payload = json.loads(_unb64(body_b64))
    payload.update(changes)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"{_b64(body)}.{signature}"
