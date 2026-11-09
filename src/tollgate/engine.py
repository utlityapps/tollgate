"""The decision engine.

One purchase request flows through:

    signed quotes -> mandate policy -> detectors -> judge -> APPROVE / ESCALATE / DENY
                                                                |           |
                                                         PayPal order   human review

Only deterministic rules can DENY. The LLM judge can only escalate to a human.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from . import catalog, detectors, policy, quotes
from .config import Settings
from .judge import Judge, JudgeInput, JudgeVerdict, build_judge
from .models import (
    SEVERITY_SCORE,
    Decision,
    Finding,
    LineItem,
    Mandate,
    MandateIn,
    Outcome,
    PurchaseRequest,
    Severity,
    money,
)
from .paypal import MockPayPal, PayPalClient, PayPalError, PayPalOrder, PaymentsBackend
from .store import Store

CATALOG_CURRENCY = "USD"
COUNTED = ("order_created", "captured")  # statuses that count as spend
VELOCITY_STATUSES = COUNTED + ("pending_review",)
DENY_RISK = 0.80
ESCALATE_RISK = 0.35
REVIEW_TTL = timedelta(hours=24)
ALL_LAYERS = frozenset({"detectors", "judge"})
ESCALATING_CODES = frozenset({"ABOVE_AUTO_APPROVE", "JUDGE_ERROR"})
ZERO = Decimal("0.00")


class EngineError(Exception):
    """A valid request that the decision's current state does not allow (HTTP 409)."""


class NotFound(KeyError):
    """Unknown mandate, product or decision (HTTP 404)."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def _clip(text: Any, limit: int) -> str:
    return " ".join(str(text).split())[:limit]


def risk_score(findings: Iterable[Finding], *, include_judge: bool = True) -> float:
    """Noisy-OR of the strongest finding per code, so repeats of one signal don't pile up."""
    strongest: dict[str, float] = {}
    for f in findings:
        if not include_judge and f.source == "judge":
            continue
        strongest[f.code] = max(strongest.get(f.code, 0.0), SEVERITY_SCORE[f.severity])
    safe = 1.0
    for score in strongest.values():
        safe *= 1.0 - score
    return round(1.0 - safe, 3)


def aggregate(findings: Sequence[Finding]) -> tuple[Outcome, float]:
    """Turn findings into an outcome.

    DENY needs a blocking finding or enough *rule-based* risk. Judge findings are left out of
    that sum on purpose: an LLM opinion alone can send a purchase to a human, never reject it.
    """
    risk = risk_score(findings)
    rule_risk = risk_score(findings, include_judge=False)
    blocked = any(f.blocking or f.severity is Severity.CRITICAL for f in findings)
    if blocked or rule_risk >= DENY_RISK:
        return Outcome.DENY, max(risk, 0.95) if blocked else risk
    if risk >= ESCALATE_RISK or any(f.code in ESCALATING_CODES for f in findings):
        return Outcome.ESCALATE, max(risk, ESCALATE_RISK)
    return Outcome.APPROVE, risk


def _reasons(findings: Sequence[Finding]) -> list[str]:
    ranked = sorted(
        (f for f in findings if f.severity is not Severity.INFO),
        key=lambda f: (-SEVERITY_SCORE[f.severity], f.code),
    )
    seen: set[str] = set()
    out: list[str] = []
    for f in ranked:
        if f.detail not in seen:
            seen.add(f.detail)
            out.append(f.detail)
    return out[:8]


def _order_problem(decision: Decision, order: PayPalOrder) -> str | None:
    """Compare what PayPal holds with what Tollgate approved."""
    if order.custom_id != decision.id:
        return "PayPal order belongs to a different Tollgate decision"
    if order.currency != decision.currency:
        return f"PayPal order currency {order.currency} differs from approved {decision.currency}"
    if order.amount != decision.total:
        return f"PayPal order amount {order.amount} differs from approved {decision.total}"
    return None


class Engine:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        payments: PaymentsBackend,
        judge: Judge,
        *,
        clock: Callable[[], datetime] | None = None,
        layers: Iterable[str] = ALL_LAYERS,
    ) -> None:
        self.s = settings
        self.store = store
        self.payments = payments
        self.judge = judge
        self.layers = frozenset(layers)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    def now(self) -> datetime:
        return self._clock()

    # --- mandates --------------------------------------------------------------------
    def create_mandate(self, data: MandateIn) -> Mandate:
        currency = data.currency.upper()
        if currency != CATALOG_CURRENCY:
            raise ValueError(f"the demo marketplace prices in {CATALOG_CURRENCY}")
        per_order, daily, auto = (
            money(data.per_order_limit),
            money(data.daily_limit),
            money(data.auto_approve_below),
        )
        if per_order > daily:
            raise ValueError("per_order_limit cannot exceed daily_limit")
        if auto > per_order:
            raise ValueError("auto_approve_below cannot exceed per_order_limit")
        now = self.now()
        fields = data.model_dump()
        fields.update(
            currency=currency,
            per_order_limit=per_order,
            daily_limit=daily,
            auto_approve_below=auto,
            allowed_categories=[c.strip().lower() for c in data.allowed_categories if c.strip()],
            allowed_merchants=[m.strip() for m in data.allowed_merchants if m.strip()],
            id=_new_id("mdt"),
            created_at=now,
            expires_at=now + timedelta(hours=data.ttl_hours),
        )
        mandate = Mandate(**fields)
        with self._lock:
            self.store.save_mandate(mandate)
        return mandate

    def get_mandate(self, mandate_id: str) -> Mandate:
        mandate = self.store.get_mandate(mandate_id)
        if mandate is None:
            raise NotFound("mandate")
        return mandate

    def list_mandates(self) -> list[Mandate]:
        return self.store.list_mandates()

    def revoke_mandate(self, mandate_id: str) -> Mandate:
        with self._lock:
            mandate = self.get_mandate(mandate_id)
            mandate.active = False
            self.store.save_mandate(mandate)
            return mandate

    # --- quotes ----------------------------------------------------------------------
    def issue_quote(self, mandate_id: str, product_id: str, quantity: int = 1) -> dict[str, Any]:
        mandate = self.get_mandate(mandate_id)
        product = catalog.get(product_id)
        if product is None:
            raise NotFound("product")
        if not 1 <= quantity <= 50:
            raise ValueError("quantity must be between 1 and 50")
        now = self.now()
        if not mandate.active or now >= mandate.expires_at:
            raise EngineError("the mandate is not active")
        merchant = catalog.merchant(product.merchant_id)
        token = quotes.issue(
            self.s.signing_key,
            mandate_id=mandate.id,
            product_id=product.id,
            merchant_id=product.merchant_id,
            unit_price=product.price,
            currency=CATALOG_CURRENCY,
            quantity=quantity,
            ttl_seconds=self.s.quote_ttl_seconds,
            now=now.timestamp(),
        )
        return {
            "quote": token,
            "product_id": product.id,
            "name": product.name,
            "merchant_id": product.merchant_id,
            "merchant_name": merchant.name if merchant else product.merchant_id,
            "unit_price": str(product.price),
            "quantity": quantity,
            "currency": CATALOG_CURRENCY,
            "line_total": str(money(product.price * quantity)),
            "expires_in_seconds": self.s.quote_ttl_seconds,
        }

    # --- the decision ----------------------------------------------------------------
    def decide(self, req: PurchaseRequest) -> Decision:
        with self._lock:
            now = self.now()
            decision = Decision(
                id=_new_id("dec"),
                created_at=now,
                mandate_id=req.mandate_id,
                agent_id=req.agent_id,
                outcome=Outcome.DENY,
                status="denied",
                justification=_clip(req.justification, 500),
            )
            findings: list[Finding] = []
            mandate = self.store.get_mandate(req.mandate_id)
            if mandate is None:
                findings.append(
                    Finding(
                        code="UNKNOWN_MANDATE",
                        severity=Severity.CRITICAL,
                        detail="No such mandate",
                        source="policy",
                        blocking=True,
                    )
                )
                decision.judge_source = "skipped"
                return self._finish(decision, findings)

            items, quote_findings = self._open_quotes(req, decision.id, now)
            findings += quote_findings
            if items:
                decision.items = items
                decision.total = money(sum((i.total for i in items), ZERO))
                decision.currency = items[0].currency
                merchants = {i.merchant_id: i.merchant_name for i in items}
                if len(merchants) == 1:
                    decision.merchant_id, decision.merchant_name = next(iter(merchants.items()))
                else:
                    decision.merchant_name = "multiple merchants"
                spent = self.store.spent_since(mandate.id, now - timedelta(hours=24), COUNTED)
                findings += policy.evaluate(
                    mandate, items, total=decision.total, spent_24h=spent, now=now
                )
                if "detectors" in self.layers:
                    findings += self._detect(mandate, items, req, now)

            blocked = any(f.blocking or f.severity is Severity.CRITICAL for f in findings)
            if "judge" in self.layers and items and not blocked:
                findings += self._judge(mandate, items, decision, req)
            elif blocked:
                decision.judge_source = "skipped (already denied by rules)"
            else:
                decision.judge_source = "off"
            return self._finish(decision, findings)

    def _open_quotes(
        self, req: PurchaseRequest, decision_id: str, now: datetime
    ) -> tuple[list[LineItem], list[Finding]]:
        items: list[LineItem] = []
        findings: list[Finding] = []
        seen: set[str] = set()

        def reject(code: str, detail: str) -> None:
            findings.append(
                Finding(
                    code=code,
                    severity=Severity.CRITICAL,
                    detail=detail,
                    source="quote",
                    blocking=True,
                )
            )

        for token in req.quotes:
            try:
                payload = quotes.verify(self.s.signing_key, token, now=now.timestamp())
            except quotes.QuoteError as exc:
                reject("QUOTE_INVALID", f"A quote was rejected: {exc}")
                continue
            if payload.get("mid") != req.mandate_id:
                reject("QUOTE_WRONG_MANDATE", "A quote was issued for a different mandate")
                continue
            qid = str(payload.get("qid", ""))
            if qid in seen:
                reject("QUOTE_DUPLICATE", "The same quote appears twice in one request")
                continue
            seen.add(qid)
            if not self.store.claim_quote(qid, decision_id):
                reject("QUOTE_REPLAY", "A quote was already used (replay attempt)")
                continue
            product = catalog.get(str(payload.get("pid", "")))
            merchant = catalog.merchant(str(payload.get("mer", "")))
            if product is None or merchant is None:
                reject("QUOTE_UNKNOWN_PRODUCT", "A quote refers to an unknown product or merchant")
                continue
            try:
                items.append(
                    LineItem(
                        product_id=product.id,
                        name=product.name,
                        category=product.category,
                        merchant_id=merchant.id,
                        merchant_name=merchant.name,
                        unit_price=Decimal(str(payload["px"])),
                        quantity=int(payload["qty"]),
                        currency=str(payload["cur"]),
                    )
                )
            except (KeyError, TypeError, ValueError, ArithmeticError):
                reject("QUOTE_INVALID", "A quote has unreadable contents")
        return items, findings

    def _detect(
        self, mandate: Mandate, items: list[LineItem], req: PurchaseRequest, now: datetime
    ) -> list[Finding]:
        """Scan everything an attacker could have written: listings, reviews, agent text."""
        listing: dict[str, str] = {}
        reviews: dict[str, str] = {}
        for item in items:
            key = f"item.{item.product_id}"
            listing[f"{key}.name"] = item.name
            listing[f"{key}.category"] = item.category
            product = catalog.get(item.product_id)
            if product is not None:
                listing[f"{key}.description"] = product.description
                for n, review in enumerate(product.reviews, 1):
                    reviews[f"{key}.review{n}"] = review
        agent_text = {"justification": req.justification, "context": req.context}
        findings = detectors.scan_untrusted({**listing, **reviews, **agent_text})
        findings += detectors.scan_risky_terms({**listing, "justification": req.justification})
        findings += detectors.scan_urgency({**listing, "justification": req.justification})

        bought_from = {i.merchant_id: i.merchant_name for i in items}
        verified = [
            m.name for m in catalog.MERCHANTS.values() if m.verified and m.id not in bought_from
        ]
        for name in bought_from.values():
            findings += detectors.check_merchant_lookalike(name, verified)

        prior = self.store.recent_times(mandate.id, now - timedelta(minutes=10), VELOCITY_STATUSES)
        findings += detectors.check_velocity(prior, now)
        return findings

    def _judge(
        self, mandate: Mandate, items: list[LineItem], decision: Decision, req: PurchaseRequest
    ) -> list[Finding]:
        inp = JudgeInput(
            task=mandate.task,
            justification=req.justification,
            items=tuple(items),
            merchant_name=decision.merchant_name or "",
            total=decision.total,
            currency=decision.currency,
        )
        try:
            verdict: JudgeVerdict = self.judge.review(inp)
        except Exception as exc:  # fail closed: a broken judge means a human looks
            decision.judge_source = "error"
            decision.judge_summary = "The purchase judge failed"
            return [
                Finding(
                    code="JUDGE_ERROR",
                    severity=Severity.MEDIUM,
                    detail="The purchase judge failed, so a human must review this order",
                    source="judge",
                    evidence=exc.__class__.__name__,
                )
            ]
        decision.judge_source = verdict.source
        decision.judge_summary = verdict.summary
        if not verdict.suspicious:
            return []
        return [
            Finding(
                code="JUDGE_SUSPICIOUS",
                severity=Severity.MEDIUM,  # capped: the judge can escalate, never deny
                detail=verdict.summary or "The purchase may not match the owner's task",
                source="judge",
                evidence=",".join(verdict.flags),
            )
        ]

    def _finish(self, decision: Decision, findings: list[Finding]) -> Decision:
        outcome, risk = aggregate(findings)
        decision.outcome = outcome
        decision.risk = risk
        decision.findings = findings
        decision.reasons = _reasons(findings)
        self._event(decision, "decided", outcome.value)
        if outcome is Outcome.DENY:
            decision.status = "denied"
        elif outcome is Outcome.ESCALATE:
            decision.status = "pending_review"
        else:
            self._open_order(decision)
        self.store.save_decision(decision)
        return decision

    # --- human review ----------------------------------------------------------------
    def human_approve(self, decision_id: str, reviewer: str = "admin", note: str = "") -> Decision:
        with self._lock:
            d = self.get_decision(decision_id)
            if d.status != "pending_review":
                raise EngineError(f"decision is '{d.status}', not 'pending_review'")
            now = self.now()
            if now - d.created_at > REVIEW_TTL:
                d.status = "expired"
                self._event(d, "expired", "review window passed")
                self.store.save_decision(d)
                raise EngineError("the review window has expired; ask the agent to request again")
            mandate = self.store.get_mandate(d.mandate_id)
            if mandate is None:
                problems = [
                    Finding(
                        code="UNKNOWN_MANDATE",
                        severity=Severity.CRITICAL,
                        detail="The mandate no longer exists",
                        source="policy",
                        blocking=True,
                    )
                ]
            else:
                # Time-of-check/time-of-use: limits are enforced again at approval time.
                spent = self.store.spent_since(d.mandate_id, now - timedelta(hours=24), COUNTED)
                problems = [
                    f
                    for f in policy.evaluate(
                        mandate, d.items, total=d.total, spent_24h=spent, now=now
                    )
                    if f.blocking
                ]
            if problems:
                d.findings += problems
                d.reasons = _reasons(d.findings)
                d.status = "denied"
                self._event(d, "approval_blocked", problems[0].detail)
                self.store.save_decision(d)
                return d
            self._event(d, "human_approved", f"{_clip(reviewer, 60)}: {_clip(note, 120)}")
            self._open_order(d)
            self.store.save_decision(d)
            return d

    def human_deny(self, decision_id: str, reviewer: str = "admin", note: str = "") -> Decision:
        with self._lock:
            d = self.get_decision(decision_id)
            if d.status != "pending_review":
                raise EngineError(f"decision is '{d.status}', not 'pending_review'")
            d.status = "human_denied"
            self._event(d, "human_denied", f"{_clip(reviewer, 60)}: {_clip(note, 120)}")
            self.store.save_decision(d)
            return d

    # --- payments --------------------------------------------------------------------
    def _open_order(self, d: Decision) -> None:
        base = self.s.public_base_url
        try:
            order = self.payments.create_order(
                request_id=f"tg-create-{d.id}",
                items=d.items,
                currency=d.currency,
                description=f"Tollgate order {d.id}",
                custom_id=d.id,
                return_url=f"{base}/paypal/return",
                cancel_url=f"{base}/paypal/cancel",
            )
            problem = _order_problem(d, order)
        except PayPalError as exc:
            self._payment_error(d, f"PayPal order could not be created: {exc}")
            return
        if problem:
            self._payment_error(d, problem)
            return
        d.paypal_order_id = order.id
        d.approve_url = order.approve_url
        d.status = "order_created"
        self._event(d, "order_created", f"{self.payments.name} order {order.id}")

    def _payment_error(self, d: Decision, detail: str) -> None:
        d.status = "payment_error"
        d.findings.append(
            Finding(
                code="PAYMENT_ERROR",
                severity=Severity.HIGH,
                detail="The payment provider returned an error",
                source="payments",
                evidence=_clip(detail, 200),
            )
        )
        self._event(d, "payment_error", detail)

    def capture(self, decision_id: str) -> Decision:
        """Capture an approved PayPal order, after re-checking it matches what we approved."""
        with self._lock:
            d = self.get_decision(decision_id)
            if d.status == "captured":
                return d
            if d.status not in ("order_created", "capture_failed") or not d.paypal_order_id:
                raise EngineError(f"cannot capture: decision is '{d.status}'")
            try:
                order = self.payments.get_order(d.paypal_order_id)
            except PayPalError as exc:
                raise EngineError(f"PayPal lookup failed: {exc}") from exc
            problem = _order_problem(d, order)
            if problem:
                return self._block_capture(d, problem)
            if order.status == "COMPLETED":
                return self._mark_captured(d, order)
            if order.status != "APPROVED":
                return d  # the buyer has not approved yet
            try:
                done = self.payments.capture_order(order.id, request_id=f"tg-capture-{d.id}")
            except PayPalError as exc:
                d.status = "capture_failed"
                self._event(d, "capture_failed", str(exc))
                self.store.save_decision(d)
                return d
            if done.status != "COMPLETED" or (
                done.capture_amount is not None and done.capture_amount != d.total
            ):
                return self._block_capture(d, "PayPal captured something other than what was approved")
            return self._mark_captured(d, done)

    def _block_capture(self, d: Decision, detail: str) -> Decision:
        d.status = "capture_blocked"
        d.findings.append(
            Finding(
                code="ORDER_MISMATCH",
                severity=Severity.CRITICAL,
                detail=detail,
                source="payments",
                blocking=True,
            )
        )
        d.reasons = _reasons(d.findings)
        self._event(d, "capture_blocked", detail)
        self.store.save_decision(d)
        return d

    def _mark_captured(self, d: Decision, order: PayPalOrder) -> Decision:
        d.status = "captured"
        d.capture_id = order.capture_id
        self._event(d, "captured", f"capture {order.capture_id or 'confirmed'}")
        self.store.save_decision(d)
        return d

    def refund(self, decision_id: str, reviewer: str = "admin", note: str = "") -> Decision:
        """Give a captured payment back. Humans only: no agent route reaches this."""
        with self._lock:
            d = self.get_decision(decision_id)
            if d.status == "refunded":
                return d  # already done, so a repeat click is harmless
            if d.status != "captured" or not d.capture_id:
                raise EngineError(f"cannot refund: decision is '{d.status}', not 'captured'")
            attempt = 1 + sum(1 for e in d.events if e["type"] == "refund_failed")
            try:
                refund = self.payments.refund_capture(
                    d.capture_id,
                    request_id=f"tg-refund-{d.id}-{attempt}",
                    amount=d.total,
                    currency=d.currency,
                    note=_clip(note, 120) or "Refund requested by the owner",
                )
            except PayPalError as exc:
                self._event(d, "refund_failed", str(exc))
                self.store.save_decision(d)
                raise EngineError(f"PayPal refused the refund: {exc}") from exc
            if (
                refund.status not in ("COMPLETED", "PENDING")
                or refund.amount != d.total
                or refund.currency != d.currency
            ):
                self._event(
                    d, "refund_failed", f"PayPal returned {refund.status} {refund.amount} {refund.currency}"
                )
                self.store.save_decision(d)
                raise EngineError(f"the refund did not complete (PayPal status {refund.status})")
            d.status = "refunded"
            d.refund_id = refund.id
            self._event(
                d,
                "refunded",
                f"{_clip(reviewer, 60)}: {_clip(note, 120)} (refund {refund.id}, {refund.status.lower()})",
            )
            self.store.save_decision(d)
            return d

    def refresh(self, decision_id: str) -> Decision:
        """Poll: capture the order if the buyer approved it since we last looked."""
        with self._lock:
            d = self.get_decision(decision_id)
            if d.status in ("order_created", "capture_failed"):
                try:
                    return self.capture(decision_id)
                except EngineError:
                    return self.get_decision(decision_id)
            return d

    def apply_webhook(self, event: dict[str, Any]) -> dict[str, Any]:
        """Handle a PayPal webhook that has already passed signature verification.

        Amounts in the payload are never trusted: capture() re-reads the order from PayPal.
        """
        kind = str(event.get("event_type", ""))
        resource = event.get("resource") or {}
        if kind == "CHECKOUT.ORDER.APPROVED":
            order_id = resource.get("id")
        else:
            related = (resource.get("supplementary_data") or {}).get("related_ids") or {}
            order_id = related.get("order_id")
        decision = self.store.find_by_order(str(order_id)) if order_id else None
        if decision is None:
            return {"handled": False, "reason": "unknown order"}
        with self._lock:
            if kind in ("CHECKOUT.ORDER.APPROVED", "PAYMENT.CAPTURE.COMPLETED"):
                try:
                    decision = self.capture(decision.id)
                except EngineError as exc:
                    return {"handled": False, "reason": str(exc)}
            elif kind in ("PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.REFUNDED", "PAYMENT.CAPTURE.REVERSED"):
                decision = self.get_decision(decision.id)
                new_status = {
                    "PAYMENT.CAPTURE.DENIED": "capture_failed",
                    "PAYMENT.CAPTURE.REFUNDED": "refunded",
                    "PAYMENT.CAPTURE.REVERSED": "reversed",
                }[kind]
                if decision.status != new_status:  # our own refund already set it: don't log it twice
                    decision.status = new_status
                    self._event(decision, kind.lower().replace(".", "_"), "reported by PayPal webhook")
                    self.store.save_decision(decision)
            else:
                return {"handled": False, "reason": f"ignored {kind or 'event'}"}
        return {"handled": True, "status": decision.status}

    # --- reads -----------------------------------------------------------------------
    def get_decision(self, decision_id: str) -> Decision:
        decision = self.store.get_decision(decision_id)
        if decision is None:
            raise NotFound("decision")
        return decision

    def list_decisions(self, limit: int = 200) -> list[Decision]:
        return self.store.list_decisions(limit)

    def stats(self) -> dict[str, Any]:
        decisions = self.store.list_decisions(1000)
        by_outcome = {o.value: 0 for o in Outcome}
        by_status: dict[str, int] = {}
        approved = blocked = held = refunded = ZERO
        for d in decisions:
            by_outcome[d.outcome.value] += 1
            by_status[d.status] = by_status.get(d.status, 0) + 1
            if d.status in ("order_created", "captured"):
                approved += d.total
            elif d.status in ("refunded", "reversed"):
                refunded += d.total
            elif d.status == "pending_review":
                held += d.total
            elif d.outcome is Outcome.DENY or d.status == "human_denied":
                blocked += d.total
        return {
            "decisions": len(decisions),
            "by_outcome": by_outcome,
            "by_status": by_status,
            "approved_usd": str(money(approved)),
            "blocked_usd": str(money(blocked)),
            "held_usd": str(money(held)),
            "refunded_usd": str(money(refunded)),
            "pending_review": by_status.get("pending_review", 0),
        }

    def describe(self) -> dict[str, Any]:
        return {
            "payments": self.payments.name,
            "judge": getattr(self.judge, "name", "custom"),
            "layers": sorted(self.layers),
            "demo_secrets": self.s.using_demo_secrets,
        }

    def _event(self, d: Decision, kind: str, detail: str = "") -> None:
        d.events.append(
            {
                "at": self.now().isoformat(timespec="seconds"),
                "type": kind,
                "detail": _clip(detail, 200),
            }
        )


def build_engine(
    settings: Settings,
    *,
    clock: Callable[[], datetime] | None = None,
    layers: Iterable[str] = ALL_LAYERS,
    store: Store | None = None,
    payments: PaymentsBackend | None = None,
    judge: Judge | None = None,
) -> Engine:
    """Wire an engine from settings. Mock payments are used when no PayPal keys are set."""
    if payments is None:
        payments = (
            PayPalClient(
                settings.paypal_client_id,
                settings.paypal_client_secret,
                base_url=settings.paypal_base_url,
                webhook_id=settings.paypal_webhook_id,
            )
            if settings.paypal_configured
            else MockPayPal(settings.public_base_url)
        )
    return Engine(
        settings,
        store or Store(settings.db_path),
        payments,
        judge or build_judge(settings),
        clock=clock,
        layers=layers,
    )
