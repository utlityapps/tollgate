from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from tollgate.config import DEFAULT_SIGNING_KEY, Settings
from tollgate.models import Decision, LineItem, Outcome, money
from tollgate.store import Store

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


# --- settings ---------------------------------------------------------------------------


def test_defaults_are_the_public_demo_secrets() -> None:
    assert Settings().using_demo_secrets
    safe = Settings(signing_key="a-long-random-key", admin_token="x1", agent_token="y2")
    assert not safe.using_demo_secrets


def test_from_env_reads_and_trims_values() -> None:
    settings = Settings.from_env(
        {
            "TOLLGATE_SIGNING_KEY": " key ",
            "TOLLGATE_ADMIN_TOKEN": "adm",
            "TOLLGATE_AGENT_TOKEN": "agt",
            "PAYPAL_CLIENT_ID": "cid",
            "PAYPAL_CLIENT_SECRET": "sec",
            "PUBLIC_BASE_URL": "https://tollgate.example/",
            "TOLLGATE_QUOTE_TTL": "60",
        },
        load_env_file=False,
    )
    assert settings.signing_key == "key" and settings.paypal_configured and not settings.llm_configured
    assert settings.public_base_url == "https://tollgate.example" and settings.quote_ttl_seconds == 60


def test_render_url_is_used_when_no_public_url_is_set() -> None:
    settings = Settings.from_env({"RENDER_EXTERNAL_URL": "https://x.onrender.com"}, load_env_file=False)
    assert settings.public_base_url == "https://x.onrender.com"
    assert Settings.from_env({}, load_env_file=False).signing_key == DEFAULT_SIGNING_KEY


def test_live_paypal_is_refused_unless_explicitly_allowed() -> None:
    live = {"PAYPAL_BASE_URL": "https://api-m.paypal.com"}
    with pytest.raises(ValueError, match="sandbox"):
        Settings.from_env(live, load_env_file=False)
    sneaky = {"PAYPAL_BASE_URL": "https://api-m.sandbox.paypal.com.evil.example"}
    with pytest.raises(ValueError, match="sandbox"):
        Settings.from_env(sneaky, load_env_file=False)
    allowed = Settings.from_env({**live, "TOLLGATE_ALLOW_LIVE": "1"}, load_env_file=False)
    assert allowed.paypal_base_url == "https://api-m.paypal.com"


# --- store ------------------------------------------------------------------------------


def decision(
    id: str, *, status: str = "captured", total: str = "12.00", at: datetime = NOW, mandate: str = "m1"
) -> Decision:
    item = LineItem(
        product_id="p", name="n", category="c", merchant_id="m", merchant_name="M",
        unit_price=money(total), quantity=1,
    )
    return Decision(
        id=id, created_at=at, mandate_id=mandate, outcome=Outcome.APPROVE, status=status,
        total=money(total), items=[item], paypal_order_id=f"ORDER-{id}",
    )


def test_decisions_round_trip_with_exact_money() -> None:
    store = Store(":memory:")
    store.save_decision(decision("d1", total="0.10"))
    loaded = store.get_decision("d1")
    assert loaded is not None and loaded.total == Decimal("0.10") and loaded.items[0].total == Decimal("0.10")
    assert store.find_by_order("ORDER-d1").id == "d1"  # type: ignore[union-attr]
    assert store.get_decision("nope") is None and store.find_by_order("nope") is None


def test_saving_again_updates_in_place() -> None:
    store = Store(":memory:")
    first = decision("d1", status="order_created")
    store.save_decision(first)
    first.status = "captured"
    store.save_decision(first)
    assert [d.status for d in store.list_decisions()] == ["captured"]


def test_spend_counts_only_the_right_statuses_and_window() -> None:
    store = Store(":memory:")
    store.save_decision(decision("a", status="captured", total="10"))
    store.save_decision(decision("b", status="order_created", total="5"))
    store.save_decision(decision("c", status="denied", total="100"))
    store.save_decision(decision("d", status="captured", total="7", mandate="other"))
    store.save_decision(decision("e", status="captured", total="9", at=NOW - timedelta(hours=30)))
    since = NOW - timedelta(hours=24)
    assert store.spent_since("m1", since, ("order_created", "captured")) == Decimal("15.00")
    assert store.spent_since("m1", since, ("denied",)) == Decimal("100.00")
    assert store.spent_since("nobody", since, ("captured",)) == Decimal("0.00")
    assert len(store.recent_times("m1", since, ("captured", "order_created"))) == 2


def test_each_quote_can_be_claimed_once() -> None:
    store = Store(":memory:")
    assert store.claim_quote("q1", "d1") is True
    assert store.claim_quote("q1", "d2") is False
    assert store.claim_quote("q2", "d2") is True


def test_list_decisions_is_newest_first_and_limited() -> None:
    store = Store(":memory:")
    for n in range(5):
        store.save_decision(decision(f"d{n}", at=NOW + timedelta(minutes=n)))
    assert [d.id for d in store.list_decisions(3)] == ["d4", "d3", "d2"]


def test_database_persists_on_disk(tmp_path: Path) -> None:
    path = str(tmp_path / "tollgate.db")
    Store(path).save_decision(decision("d1"))
    assert Store(path).get_decision("d1") is not None
