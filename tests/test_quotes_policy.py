from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from tollgate import policy, quotes
from tollgate.models import LineItem, Mandate

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def issue(**overrides: object) -> str:
    args: dict[str, object] = dict(
        mandate_id="m1",
        product_id="p1",
        merchant_id="mer1",
        unit_price=Decimal("12"),
        currency="USD",
        quantity=2,
        ttl_seconds=60,
        now=1000.0,
    )
    args.update(overrides)
    return quotes.issue("key", **args)  # type: ignore[arg-type]


def test_quote_round_trip() -> None:
    payload = quotes.verify("key", issue(), now=1010.0)
    assert payload["px"] == "12.00" and payload["qty"] == 2 and payload["mer"] == "mer1"


def test_wrong_key_is_rejected() -> None:
    with pytest.raises(quotes.QuoteError):
        quotes.verify("other-key", issue(), now=1010.0)


def test_any_edit_breaks_the_signature() -> None:
    for change in ({"px": "0.01"}, {"mer": "evil"}, {"qty": 99}, {"mid": "m2"}):
        with pytest.raises(quotes.QuoteError, match="signature"):
            quotes.verify("key", quotes.tamper(issue(), **change), now=1010.0)


def test_quote_expires() -> None:
    with pytest.raises(quotes.QuoteError, match="expired"):
        quotes.verify("key", issue(), now=1061.0)


@pytest.mark.parametrize("token", ["", "abc", "a.b.c", "!!.zz", 123, None])
def test_malformed_quotes_are_rejected(token: object) -> None:
    with pytest.raises(quotes.QuoteError):
        quotes.verify("key", token, now=1010.0)  # type: ignore[arg-type]


def make_mandate(**overrides: object) -> Mandate:
    fields: dict[str, object] = dict(
        id="mdt_1",
        owner="o",
        task="buy cables",
        currency="USD",
        per_order_limit=Decimal("60"),
        daily_limit=Decimal("150"),
        auto_approve_below=Decimal("25"),
        allowed_categories=["electronics"],
        allowed_merchants=["m_contoso"],
        max_items_per_order=3,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    fields.update(overrides)
    return Mandate(**fields)  # type: ignore[arg-type]


def item(**overrides: object) -> LineItem:
    fields: dict[str, object] = dict(
        product_id="p",
        name="Cable",
        category="electronics",
        merchant_id="m_contoso",
        merchant_name="Contoso",
        unit_price=Decimal("12"),
        quantity=1,
        currency="USD",
    )
    fields.update(overrides)
    return LineItem(**fields)  # type: ignore[arg-type]


def codes_for(mandate: Mandate, items: list[LineItem], spent: str = "0") -> set[str]:
    total = sum((i.total for i in items), Decimal("0"))
    return {
        f.code
        for f in policy.evaluate(mandate, items, total=total, spent_24h=Decimal(spent), now=NOW)
    }


def test_clean_order_has_no_findings() -> None:
    assert codes_for(make_mandate(), [item()]) == set()


@pytest.mark.parametrize(
    ("mandate_kw", "item_kw", "spent", "expected"),
    [
        ({}, {"merchant_id": "m_other"}, "0", "MERCHANT_NOT_ALLOWED"),
        ({}, {"category": "gift-cards"}, "0", "CATEGORY_NOT_ALLOWED"),
        ({}, {"currency": "EUR"}, "0", "CURRENCY_MISMATCH"),
        ({}, {"quantity": 4}, "0", "QUANTITY_LIMIT"),
        ({}, {"unit_price": Decimal("61")}, "0", "PER_ORDER_LIMIT"),
        ({}, {}, "145", "DAILY_LIMIT"),
        ({"active": False}, {}, "0", "MANDATE_INACTIVE"),
        ({"expires_at": NOW - timedelta(seconds=1)}, {}, "0", "MANDATE_EXPIRED"),
    ],
)
def test_each_rule_blocks(mandate_kw: dict, item_kw: dict, spent: str, expected: str) -> None:
    findings = policy.evaluate(
        make_mandate(**mandate_kw),
        [item(**item_kw)],
        total=item(**item_kw).total,
        spent_24h=Decimal(spent),
        now=NOW,
    )
    hits = [f for f in findings if f.code == expected]
    assert hits and all(f.blocking for f in hits)


def test_two_merchants_in_one_order_are_blocked() -> None:
    mandate = make_mandate(allowed_merchants=["m_contoso", "m_northwind"])
    found = codes_for(mandate, [item(), item(merchant_id="m_northwind", merchant_name="Northwind")])
    assert "MULTI_MERCHANT" in found


def test_wildcard_merchant_allows_any_seller() -> None:
    mandate = make_mandate(allowed_merchants=["*"])
    assert codes_for(mandate, [item(merchant_id="m_anyone")]) == set()


def test_above_auto_approve_is_not_blocking() -> None:
    findings = policy.evaluate(
        make_mandate(), [item(unit_price=Decimal("30"))], total=Decimal("30"), spent_24h=Decimal("0"), now=NOW
    )
    assert [f.code for f in findings] == ["ABOVE_AUTO_APPROVE"]
    assert not findings[0].blocking
