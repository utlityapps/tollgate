"""Mandate policy: limits and allow-lists that no model can talk its way past."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from .models import Finding, LineItem, Mandate, Severity, money


def evaluate(
    mandate: Mandate,
    items: list[LineItem],
    *,
    total: Decimal,
    spent_24h: Decimal,
    now: datetime,
) -> list[Finding]:
    """Hard rules. Every violation here is blocking: the purchase is denied outright."""
    out: list[Finding] = []

    def block(code: str, detail: str) -> None:
        out.append(
            Finding(
                code=code,
                severity=Severity.CRITICAL,
                detail=detail,
                source="policy",
                blocking=True,
            )
        )

    if not mandate.active:
        block("MANDATE_INACTIVE", "The mandate has been revoked")
    if now >= mandate.expires_at:
        block("MANDATE_EXPIRED", "The mandate has expired")

    if len({i.merchant_id for i in items}) > 1:
        block("MULTI_MERCHANT", "One order can pay one merchant only")

    allowed_merchants = {m.lower() for m in mandate.allowed_merchants}
    allowed_categories = {c.lower() for c in mandate.allowed_categories}
    for item in items:
        if item.currency != mandate.currency:
            block("CURRENCY_MISMATCH", f"{item.name} is priced in {item.currency}, not {mandate.currency}")
        if "*" not in allowed_merchants and item.merchant_id.lower() not in allowed_merchants:
            block("MERCHANT_NOT_ALLOWED", f"Merchant '{item.merchant_name}' is not on the mandate's allow-list")
        if item.category.lower() not in allowed_categories:
            block("CATEGORY_NOT_ALLOWED", f"Category '{item.category}' is not allowed by the mandate")

    quantity = sum(i.quantity for i in items)
    if quantity > mandate.max_items_per_order:
        block("QUANTITY_LIMIT", f"{quantity} items exceeds the limit of {mandate.max_items_per_order} per order")
    if total > mandate.per_order_limit:
        block("PER_ORDER_LIMIT", f"{money(total)} exceeds the {money(mandate.per_order_limit)} per-order limit")
    if spent_24h + total > mandate.daily_limit:
        block(
            "DAILY_LIMIT",
            f"{money(spent_24h)} already spent in 24 h; adding {money(total)} would pass the "
            f"{money(mandate.daily_limit)} daily limit",
        )

    if total > mandate.auto_approve_below:
        out.append(
            Finding(
                code="ABOVE_AUTO_APPROVE",
                severity=Severity.LOW,
                detail=(
                    f"{money(total)} is above the {money(mandate.auto_approve_below)} "
                    "auto-approve limit, so a human must approve"
                ),
                source="policy",
            )
        )

    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for finding in out:
        key = (finding.code, finding.detail)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
