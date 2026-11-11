from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tollgate import catalog
from tollgate.api import create_app
from tollgate.config import Settings
from tollgate.engine import ALL_LAYERS, Engine
from tollgate.judge import HeuristicJudge, Judge, JudgeChain
from tollgate.models import Decision, Mandate, MandateIn, PurchaseRequest
from tollgate.paypal import MockPayPal, PaymentsBackend
from tollgate.store import Store

START = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
AGENT = {"Authorization": "Bearer test-agent"}
ADMIN = {"Authorization": "Bearer test-admin"}


class Clock:
    """A clock the tests can move forward."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


class World:
    """An engine, a clock, mock PayPal and a demo mandate, ready to shop in."""

    def __init__(
        self,
        settings: Settings,
        clock: Clock,
        *,
        judge: Judge | None = None,
        payments: PaymentsBackend | None = None,
        layers: Iterable[str] = ALL_LAYERS,
    ) -> None:
        self.clock = clock
        self.payments: Any = payments or MockPayPal(settings.public_base_url, accept_test_webhooks=True)
        self.engine = Engine(
            settings,
            Store(":memory:"),
            self.payments,
            judge or JudgeChain(HeuristicJudge()),
            clock=clock,
            layers=layers,
        )
        self.mandate: Mandate = self.new_mandate()

    def new_mandate(self, **overrides: Any) -> Mandate:
        return self.engine.create_mandate(MandateIn(**{**catalog.DEMO_MANDATE, **overrides}))  # type: ignore[arg-type]

    def quote(self, product_id: str, qty: int = 1, *, mandate: Mandate | None = None) -> str:
        target = mandate or self.mandate
        return str(self.engine.issue_quote(target.id, product_id, qty)["quote"])

    def buy(
        self,
        product_id: str,
        qty: int = 1,
        *,
        mandate: Mandate | None = None,
        quote: str | None = None,
        **fields: str,
    ) -> Decision:
        target = mandate or self.mandate
        token = quote or self.quote(product_id, qty, mandate=target)
        return self.engine.decide(PurchaseRequest(mandate_id=target.id, quotes=[token], **fields))

    def pay(self, decision: Decision) -> Decision:
        """The buyer approves the PayPal order, then Tollgate captures it."""
        assert decision.paypal_order_id is not None
        self.payments.approve(decision.paypal_order_id)
        return self.engine.capture(decision.id)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        db_path=":memory:",
        signing_key="test-signing-key",
        admin_token="test-admin",
        agent_token="test-agent",
        public_base_url="http://testserver",
    )


@pytest.fixture
def make_world(settings: Settings, clock: Clock) -> Any:
    def _make(**kwargs: Any) -> World:
        return World(settings, clock, **kwargs)

    return _make


@pytest.fixture
def world(make_world: Any) -> World:
    return make_world()


@pytest.fixture
def client(world: World) -> TestClient:
    return TestClient(create_app(engine=world.engine), base_url="http://testserver")
