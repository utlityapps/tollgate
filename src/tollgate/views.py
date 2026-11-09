"""What each audience is allowed to see.

Agents get short reasons from a fixed vocabulary. Text an attacker wrote (listing copy,
merchant names, matched snippets) is never echoed back to an agent, because echoing it
would hand the attacker a second chance to inject. Admins get everything, as plain data.
"""

from __future__ import annotations

from typing import Any

from . import catalog
from .models import Decision, Finding, Mandate

PUBLIC_REASONS: dict[str, str] = {
    "UNKNOWN_MANDATE": "Unknown mandate",
    "MANDATE_INACTIVE": "The mandate was revoked",
    "MANDATE_EXPIRED": "The mandate has expired",
    "MULTI_MERCHANT": "One order can pay one merchant only",
    "CURRENCY_MISMATCH": "Currency does not match the mandate",
    "MERCHANT_NOT_ALLOWED": "Merchant is not on the mandate's allow-list",
    "CATEGORY_NOT_ALLOWED": "Category is not allowed by the mandate",
    "QUANTITY_LIMIT": "Too many items for one order",
    "PER_ORDER_LIMIT": "Over the per-order limit",
    "DAILY_LIMIT": "Over the daily limit",
    "ABOVE_AUTO_APPROVE": "Above the auto-approve limit, so a human must approve",
    "QUOTE_INVALID": "A quote was invalid, altered or expired",
    "QUOTE_WRONG_MANDATE": "A quote belongs to a different mandate",
    "QUOTE_DUPLICATE": "A quote was listed twice",
    "QUOTE_REPLAY": "A quote was already used",
    "QUOTE_UNKNOWN_PRODUCT": "A quote refers to an unknown product",
    "LOOKALIKE_MERCHANT": "The merchant name imitates another business",
    "LOOKALIKE_BRAND": "The merchant name imitates a well-known brand",
    "RISKY_CATEGORY": "High-risk payment category (gift cards, crypto, wire transfers)",
    "URGENCY_PRESSURE": "The listing pressures the buyer to act now",
    "VELOCITY": "Too many orders in a short time",
    "JUDGE_SUSPICIOUS": "The purchase does not fit the owner's task",
    "JUDGE_ERROR": "The purchase reviewer failed, so a human must check",
    "PAYMENT_ERROR": "The payment provider returned an error",
    "ORDER_MISMATCH": "The payment order did not match what was approved",
}
_HIDDEN = frozenset(
    {
        "HIDDEN_UNICODE_TEXT",
        "OBFUSCATED_TEXT",
        "ENCODED_INSTRUCTION",
        "INVISIBLE_CHARACTERS",
        "BIDI_CONTROL",
        "HIDDEN_HTML_COMMENT",
        "HIDDEN_STYLED_TEXT",
    }
)


def public_reason(code: str) -> str:
    if code in PUBLIC_REASONS:
        return PUBLIC_REASONS[code]
    if code.startswith("INJECTION_"):
        return "Listing or request text contains instructions aimed at AI agents"
    if code in _HIDDEN:
        return "Hidden or obfuscated text was found"
    return "Flagged by a safety check"


def public_reasons(findings: list[Finding]) -> list[str]:
    seen: dict[str, None] = {}
    for f in findings:
        if f.code == "ABOVE_AUTO_APPROVE" and len(findings) > 1:
            continue
        seen.setdefault(public_reason(f.code))
    return list(seen)[:6]


_NEXT_STEP = {
    "order_created": (
        "Ask the owner to approve the payment at approve_url, then poll purchase_status."
    ),
    "pending_review": (
        "A human must approve this order in the Tollgate dashboard. Poll purchase_status."
    ),
    "denied": "Do not retry with the same quotes. Tell the owner what was blocked and why.",
    "human_denied": "The owner declined this order. Do not retry it.",
    "captured": "Payment complete. Nothing more to do.",
    "refunded": "The owner got this payment back. Do not buy it again unless asked.",
    "reversed": "The payment was reversed by PayPal. Tell the owner; do not retry on your own.",
    "payment_error": "The payment provider failed. Tell the owner; do not retry on your own.",
    "capture_blocked": "Payment was stopped because it did not match the approved order.",
}


def public_view(d: Decision) -> dict[str, Any]:
    """The agent-facing view of a decision."""
    return {
        "id": d.id,
        "outcome": d.outcome.value,
        "status": d.status,
        "total": str(d.total),
        "currency": d.currency,
        "items": [
            {"product_id": i.product_id, "quantity": i.quantity, "unit_price": str(i.unit_price)}
            for i in d.items
        ],
        "reasons": public_reasons(d.findings),
        "approve_url": d.approve_url if d.status == "order_created" else None,
        "next_step": _NEXT_STEP.get(d.status, "Poll purchase_status."),
    }


def admin_view(d: Decision) -> dict[str, Any]:
    """Everything, for the dashboard. The dashboard renders it as text, never as HTML."""
    return d.model_dump(mode="json")


def mandate_view(m: Mandate) -> dict[str, Any]:
    data = m.model_dump(mode="json")
    data["allowed_merchant_names"] = [
        (catalog.merchant(mid).name if catalog.merchant(mid) else mid)
        for mid in m.allowed_merchants
    ]
    return data


def listing_view(product: catalog.Product) -> dict[str, Any]:
    merchant = catalog.merchant(product.merchant_id)
    return {
        "product_id": product.id,
        "name": product.name,
        "description": product.description,
        "price": str(product.price),
        "currency": "USD",
        "category": product.category,
        "merchant_id": product.merchant_id,
        "merchant_name": merchant.name if merchant else product.merchant_id,
        "reviews": list(product.reviews),
    }
