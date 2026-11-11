"""HTTP API: agent endpoints, admin endpoints, PayPal return/webhook, and the dashboard.

Two bearer tokens keep the roles apart. The *agent* token can search, request quotes and
ask to buy; it cannot read decisions in full, approve anything or change a mandate. The
*admin* token drives the dashboard.
"""

from __future__ import annotations

import html
import json
import logging
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import __version__, catalog
from .config import DEMO_ADMIN_TOKEN, Settings
from .engine import Engine, EngineError, NotFound, build_engine
from .models import MandateIn, PurchaseRequest
from .paypal import MockPayPal, PayPalError
from .views import admin_view, listing_view, mandate_view, public_view

log = logging.getLogger("tollgate")
STATIC = Path(__file__).parent / "static"

DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; img-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
MAX_WEBHOOK_BYTES = 256_000


class QuoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mandate_id: str = Field(min_length=1, max_length=64)
    product_id: str = Field(min_length=1, max_length=64)
    quantity: int = Field(default=1, ge=1, le=50)


class ReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer: str = Field(default="admin", max_length=60)
    note: str = Field(default="", max_length=200)


def _simple_page(title: str, body: str, status: int = 200) -> HTMLResponse:
    page = (
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;"
        "padding:0 1rem;color:#1b1f24}h1{font-size:1.3rem}.tag{display:inline-block;"
        "background:#fff3cd;border:1px solid #e0c36a;border-radius:4px;padding:.1rem .5rem;"
        "font-size:.8rem}button{font:inherit;padding:.6rem 1.1rem;margin-right:.5rem;"
        "border-radius:6px;border:1px solid #888;cursor:pointer}"
        "button.go{background:#0b6b3a;color:#fff;border-color:#0b6b3a}"
        "dl{display:grid;grid-template-columns:8rem 1fr;gap:.25rem 1rem}dt{color:#555}"
        "dd{margin:0}</style>"
        f"<main><h1>{html.escape(title)}</h1>{body}</main>"
    )
    return HTMLResponse(page, status_code=status, headers={"Content-Security-Policy": PAGE_CSP})


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    engine = engine or build_engine(settings or Settings.from_env())
    cfg = engine.s
    app = FastAPI(title="Tollgate", version=__version__, redoc_url=None)
    app.state.engine = engine

    if cfg.using_demo_secrets:
        log.warning(
            "Tollgate is running with DEMO secrets. Set TOLLGATE_SIGNING_KEY, "
            "TOLLGATE_ADMIN_TOKEN and TOLLGATE_AGENT_TOKEN before exposing it."
        )

    # --- auth ------------------------------------------------------------------------
    def bearer(request: Request) -> bytes:
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        return value.strip().encode() if scheme.lower() == "bearer" else b""

    def require(*accepted: str) -> Callable[[Request], None]:
        def dependency(request: Request) -> None:
            presented = bearer(request)
            ok = [secrets.compare_digest(presented, token.encode()) for token in accepted]
            if not any(ok):
                raise HTTPException(
                    401, "invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"}
                )

        return dependency

    agent_only = Depends(require(cfg.agent_token))
    admin_only = Depends(require(cfg.admin_token))
    either = Depends(require(cfg.agent_token, cfg.admin_token))

    def call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except NotFound as exc:
            raise HTTPException(404, f"unknown {exc.args[0]}") from exc
        except EngineError as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[..., Any]) -> Any:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path.startswith("/static/"):
            # The dashboard files are reachable here too, so they get the same strict policy.
            response.headers.setdefault("Content-Security-Policy", DASHBOARD_CSP)
        return response

    # --- public ----------------------------------------------------------------------
    @app.get("/api/health")
    def health(request: Request) -> dict[str, Any]:
        info: dict[str, Any] = {"ok": True, "version": __version__, **engine.describe()}
        client = request.client.host if request.client else ""
        if cfg.admin_token == DEMO_ADMIN_TOKEN and client in LOOPBACK_HOSTS:
            # Only the public demo value, and only to a browser on this machine.
            info["admin_token_hint"] = DEMO_ADMIN_TOKEN
        return info

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(
            STATIC / "dashboard.html",
            headers={"Content-Security-Policy": DASHBOARD_CSP, "Cache-Control": "no-store"},
        )

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # --- agent endpoints -------------------------------------------------------------
    @app.get("/api/products", dependencies=[agent_only])
    def products(q: str = Query("", max_length=200), hostile: bool = False) -> list[dict[str, Any]]:
        return [listing_view(p) for p in catalog.search(q, include_hostile=hostile)]

    @app.get("/api/mandates/{mandate_id}", dependencies=[either])
    def read_mandate(mandate_id: str) -> dict[str, Any]:
        return mandate_view(call(engine.get_mandate, mandate_id))

    @app.post("/api/quotes", dependencies=[agent_only])
    def create_quote(body: QuoteRequest) -> dict[str, Any]:
        return call(engine.issue_quote, body.mandate_id, body.product_id, body.quantity)

    @app.post("/api/purchases", dependencies=[agent_only])
    def create_purchase(body: PurchaseRequest) -> dict[str, Any]:
        return public_view(engine.decide(body))

    @app.get("/api/purchases/{decision_id}", dependencies=[agent_only])
    def purchase_status(decision_id: str) -> dict[str, Any]:
        return public_view(call(engine.refresh, decision_id))

    # --- admin endpoints -------------------------------------------------------------
    @app.post("/api/mandates", dependencies=[admin_only], status_code=201)
    def create_mandate(body: MandateIn) -> dict[str, Any]:
        return mandate_view(call(engine.create_mandate, body))

    @app.get("/api/mandates", dependencies=[admin_only])
    def list_mandates() -> list[dict[str, Any]]:
        return [mandate_view(m) for m in engine.list_mandates()]

    @app.post("/api/mandates/{mandate_id}/revoke", dependencies=[admin_only])
    def revoke_mandate(mandate_id: str) -> dict[str, Any]:
        return mandate_view(call(engine.revoke_mandate, mandate_id))

    @app.get("/api/decisions", dependencies=[admin_only])
    def list_decisions(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
        return [admin_view(d) for d in engine.list_decisions(limit)]

    @app.get("/api/decisions/{decision_id}", dependencies=[admin_only])
    def read_decision(decision_id: str) -> dict[str, Any]:
        return admin_view(call(engine.get_decision, decision_id))

    @app.post("/api/decisions/{decision_id}/approve", dependencies=[admin_only])
    def approve_decision(decision_id: str, body: ReviewBody | None = None) -> dict[str, Any]:
        body = body or ReviewBody()
        return admin_view(call(engine.human_approve, decision_id, body.reviewer, body.note))

    @app.post("/api/decisions/{decision_id}/deny", dependencies=[admin_only])
    def deny_decision(decision_id: str, body: ReviewBody | None = None) -> dict[str, Any]:
        body = body or ReviewBody()
        return admin_view(call(engine.human_deny, decision_id, body.reviewer, body.note))

    @app.post("/api/decisions/{decision_id}/refund", dependencies=[admin_only])
    def refund_decision(decision_id: str, body: ReviewBody | None = None) -> dict[str, Any]:
        body = body or ReviewBody()
        return admin_view(call(engine.refund, decision_id, body.reviewer, body.note))

    @app.get("/api/stats", dependencies=[admin_only])
    def stats() -> dict[str, Any]:
        return engine.stats()

    @app.post("/api/redteam/run", dependencies=[admin_only])
    def run_redteam() -> dict[str, Any]:
        from .redteam import run_scorecard  # imported lazily: it builds throwaway engines

        return run_scorecard().to_dict()

    # --- PayPal return, cancel and webhook -------------------------------------------
    @app.get("/paypal/return", include_in_schema=False)
    def paypal_return(token: str = Query("", max_length=64)) -> HTMLResponse:
        decision = engine.store.find_by_order(token) if token else None
        if decision is None:
            return _simple_page("Unknown order", "<p>No order matches that link.</p>", 404)
        decision = engine.refresh(decision.id)
        messages = {
            "captured": "Payment captured. You can close this tab.",
            "order_created": "Approval received. Waiting for PayPal to confirm the payment.",
            "capture_blocked": "Payment was stopped: the order did not match what was approved.",
            "capture_failed": "PayPal could not capture the payment.",
        }
        text = messages.get(decision.status, f"Order status: {decision.status}")
        body = f"<p>{html.escape(text)}</p><p>Decision <code>{html.escape(decision.id)}</code></p>"
        return _simple_page("Tollgate checkout", body)

    @app.get("/paypal/cancel", include_in_schema=False)
    def paypal_cancel() -> HTMLResponse:
        return _simple_page("Payment cancelled", "<p>No money moved. The order stays unpaid.</p>")

    @app.post("/webhooks/paypal", include_in_schema=False)
    async def paypal_webhook(request: Request) -> dict[str, Any]:
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(413, "webhook body too large")
        verified = await run_in_threadpool(engine.payments.verify_webhook, request.headers, body)
        if not verified:
            raise HTTPException(400, "webhook signature could not be verified")
        try:
            event = json.loads(body)
        except ValueError as exc:
            raise HTTPException(400, "invalid JSON") from exc
        if not isinstance(event, dict):
            raise HTTPException(400, "unexpected webhook payload")
        return await run_in_threadpool(engine.apply_webhook, event)

    # --- mock payment pages (only when no PayPal keys are configured) ----------------
    def mock_backend() -> MockPayPal:
        if not isinstance(engine.payments, MockPayPal):
            raise HTTPException(404, "not found")
        return engine.payments

    @app.get("/mock/pay/{order_id}", include_in_schema=False)
    def mock_pay(order_id: str) -> HTMLResponse:
        backend = mock_backend()
        try:
            order = backend.get_order(order_id)
        except PayPalError:
            return _simple_page("Unknown order", "<p>No such mock order.</p>", 404)
        safe_id = html.escape(order.id)
        details = (
            "<p><span class=tag>MOCK payment page: no real money, not PayPal</span></p>"
            f"<dl><dt>Order</dt><dd>{safe_id}</dd>"
            f"<dt>Amount</dt><dd>{html.escape(str(order.amount))} {html.escape(order.currency)}</dd>"
            f"<dt>Status</dt><dd>{html.escape(order.status)}</dd></dl>"
        )
        if order.status in ("PAYER_ACTION_REQUIRED", "CREATED"):
            details += (
                f"<form method=post action='/mock/pay/{safe_id}/approve'>"
                "<button class=go>Approve payment</button></form>"
            )
        return _simple_page("Approve this payment (mock)", details)

    @app.post("/mock/pay/{order_id}/approve", include_in_schema=False)
    def mock_approve(order_id: str) -> RedirectResponse:
        backend = mock_backend()
        try:
            backend.approve(order_id)
        except PayPalError as exc:
            raise HTTPException(404 if exc.status == 404 else 409, "cannot approve this order") from exc
        return RedirectResponse(f"/paypal/return?token={order_id}", status_code=303)

    return app
