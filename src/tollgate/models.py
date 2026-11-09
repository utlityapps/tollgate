"""Typed data models shared by the engine, API, MCP server and dashboard."""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

CENT = Decimal("0.01")


def money(value: Any) -> Decimal:
    """Round to whole cents. Money is always Decimal, never float."""
    return Decimal(str(value)).quantize(CENT, rounding=ROUND_HALF_UP)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORE: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.4,
    Severity.HIGH: 0.7,
    Severity.CRITICAL: 0.95,
}


class Outcome(str, Enum):
    APPROVE = "APPROVE"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


class Finding(BaseModel):
    """One reason a purchase looked fine or suspicious."""

    code: str
    severity: Severity
    detail: str
    source: Literal["policy", "detector", "judge", "quote", "payments"]
    evidence: str = ""
    blocking: bool = False


class MandateIn(BaseModel):
    """What the human owner signs off on before an agent may spend anything."""

    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1, max_length=120)
    task: str = Field(min_length=3, max_length=500)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    per_order_limit: Decimal = Field(gt=0)
    daily_limit: Decimal = Field(gt=0)
    auto_approve_below: Decimal = Field(ge=0)
    allowed_categories: list[str] = Field(min_length=1)
    allowed_merchants: list[str] = Field(min_length=1)
    max_items_per_order: int = Field(default=5, ge=1, le=50)
    ttl_hours: int = Field(default=24, ge=1, le=24 * 30)


class Mandate(MandateIn):
    id: str
    created_at: datetime
    expires_at: datetime
    active: bool = True


class PurchaseRequest(BaseModel):
    """What an agent sends. Note what is *not* here: no price, payee or amount.

    Those come from signed quotes, so an injected instruction cannot change them.
    """

    model_config = ConfigDict(extra="forbid")

    mandate_id: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(default="agent", max_length=64)
    quotes: list[str] = Field(min_length=1, max_length=20)
    justification: str = Field(default="", max_length=2000)
    # Untrusted text the agent read while shopping. Scanned, never obeyed.
    context: str = Field(default="", max_length=20000)


class LineItem(BaseModel):
    product_id: str
    name: str
    category: str
    merchant_id: str
    merchant_name: str
    unit_price: Decimal
    quantity: int
    currency: str = "USD"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> Decimal:
        return money(self.unit_price * self.quantity)


class Decision(BaseModel):
    id: str
    created_at: datetime
    mandate_id: str
    agent_id: str = "agent"
    outcome: Outcome
    status: str
    risk: float = 0.0
    total: Decimal = Decimal("0.00")
    currency: str = "USD"
    merchant_id: str | None = None
    merchant_name: str | None = None
    items: list[LineItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    judge_source: str = "none"
    judge_summary: str = ""
    justification: str = ""
    paypal_order_id: str | None = None
    capture_id: str | None = None
    refund_id: str | None = None
    approve_url: str | None = None
    events: list[dict[str, str]] = Field(default_factory=list)
