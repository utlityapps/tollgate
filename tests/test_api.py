from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote as urlquote

import pytest
from fastapi.testclient import TestClient

from tollgate import catalog
from tollgate.api import MAX_WEBHOOK_BYTES, create_app
from tollgate.config import Settings
from tollgate.views import PUBLIC_REASONS

from conftest import ADMIN, AGENT

AGENT_ONLY = [
    ("GET", "/api/products", None),
    ("POST", "/api/quotes", {"mandate_id": "m", "product_id": "p"}),
    ("POST", "/api/purchases", {"mandate_id": "m", "quotes": ["q"]}),
    ("GET", "/api/purchases/dec_x", None),
]
ADMIN_ONLY = [
    ("POST", "/api/mandates", dict(catalog.DEMO_MANDATE)),
    ("GET", "/api/mandates", None),
    ("POST", "/api/mandates/mdt_x/revoke", None),
    ("GET", "/api/decisions", None),
    ("GET", "/api/decisions/dec_x", None),
    ("POST", "/api/decisions/dec_x/approve", None),
    ("POST", "/api/decisions/dec_x/deny", None),
    ("POST", "/api/decisions/dec_x/refund", None),
    ("GET", "/api/stats", None),
    ("POST", "/api/redteam/run", None),
]


def call(client: TestClient, method: str, path: str, headers: dict[str, str], body: Any = None) -> Any:
    return client.request(method, path, headers=headers, json=body)


# --- who may call what ------------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), AGENT_ONLY + ADMIN_ONLY)
def test_no_token_means_401(client: TestClient, method: str, path: str, body: Any) -> None:
    response = call(client, method, path, {}, body)
    assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(("method", "path", "body"), AGENT_ONLY)
def test_admin_token_cannot_act_as_the_agent(client: TestClient, method: str, path: str, body: Any) -> None:
    assert call(client, method, path, ADMIN, body).status_code == 401


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ONLY)
def test_agent_token_cannot_reach_admin_endpoints(client: TestClient, method: str, path: str, body: Any) -> None:
    assert call(client, method, path, AGENT, body).status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Basic test-agent"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer test-agen"},
        {"Authorization": "Bearer test-agent-extra"},
        {"Authorization": "test-agent"},
        {"X-Api-Key": "test-agent"},
    ],
)
def test_malformed_credentials_are_refused(client: TestClient, header: dict[str, str]) -> None:
    assert client.get("/api/products", headers=header).status_code == 401


def test_either_token_may_read_a_mandate(client: TestClient, world: Any) -> None:
    for headers in (AGENT, ADMIN):
        response = client.get(f"/api/mandates/{world.mandate.id}", headers=headers)
        assert response.status_code == 200
        assert response.json()["allowed_merchant_names"] == [
            "Contoso Cables & Gadgets",
            "Northwind Office Supply",
        ]
    assert client.get("/api/mandates/mdt_nope", headers=AGENT).status_code == 404


def test_health_is_public_and_leaks_no_secrets(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["ok"] is True and body["payments"] == "mock" and body["judge"] == "heuristic"
    assert "admin_token_hint" not in body
    assert "test-admin" not in json.dumps(body) and "test-signing-key" not in json.dumps(body)


def test_health_shows_the_public_demo_token_only_when_it_is_the_demo_token() -> None:
    app = create_app(Settings(db_path=":memory:", signing_key="k", agent_token="a"))
    body = TestClient(app).get("/api/health").json()
    assert body["admin_token_hint"] == "demo-admin" and body["demo_secrets"] is True


# --- a purchase over HTTP, end to end ---------------------------------------------------


def test_full_purchase_over_http(client: TestClient) -> None:
    created = client.post("/api/mandates", headers=ADMIN, json=dict(catalog.DEMO_MANDATE))
    assert created.status_code == 201
    mandate_id = created.json()["id"]

    found = client.get("/api/products", headers=AGENT, params={"q": "usb-c cable"}).json()
    assert "p_usbc_cable" in {p["product_id"] for p in found}

    quote = client.post(
        "/api/quotes",
        headers=AGENT,
        json={"mandate_id": mandate_id, "product_id": "p_usbc_cable", "quantity": 1},
    ).json()
    bought = client.post(
        "/api/purchases",
        headers=AGENT,
        json={"mandate_id": mandate_id, "quotes": [quote["quote"]], "justification": "Cable for the laptop"},
    ).json()
    assert bought["outcome"] == "APPROVE" and bought["status"] == "order_created"
    assert bought["total"] == "12.00" and bought["approve_url"]

    order_id = client.get(f"/api/decisions/{bought['id']}", headers=ADMIN).json()["paypal_order_id"]
    page = client.get(f"/mock/pay/{order_id}")
    assert page.status_code == 200 and "MOCK" in page.text and "not PayPal" in page.text

    approved = client.post(f"/mock/pay/{order_id}/approve", follow_redirects=False)
    assert approved.status_code == 303 and approved.headers["location"] == f"/paypal/return?token={order_id}"
    back = client.get(approved.headers["location"])
    assert back.status_code == 200 and "Payment captured" in back.text

    status = client.get(f"/api/purchases/{bought['id']}", headers=AGENT).json()
    assert status["status"] == "captured" and status["approve_url"] is None


def test_held_order_needs_the_admin_token(client: TestClient, world: Any) -> None:
    quote = client.post(
        "/api/quotes", headers=AGENT, json={"mandate_id": world.mandate.id, "product_id": "p_desk_lamp"}
    ).json()
    held = client.post(
        "/api/purchases", headers=AGENT, json={"mandate_id": world.mandate.id, "quotes": [quote["quote"]]}
    ).json()
    assert held["outcome"] == "ESCALATE" and held["status"] == "pending_review"
    assert held["approve_url"] is None and "dashboard" in held["next_step"]

    url = f"/api/decisions/{held['id']}/approve"
    assert client.post(url, headers=AGENT).status_code == 401  # the agent cannot approve itself
    ok = client.post(url, headers=ADMIN, json={"reviewer": "alex", "note": "ok"})
    assert ok.status_code == 200 and ok.json()["status"] == "order_created"
    assert client.post(url, headers=ADMIN).status_code == 409  # only once
    assert client.post("/api/decisions/dec_nope/approve", headers=ADMIN).status_code == 404


def test_refund_endpoint_is_admin_only_and_only_for_captured_payments(client: TestClient, world: Any) -> None:
    paid = world.pay(world.buy("p_usbc_cable"))
    url = f"/api/decisions/{paid.id}/refund"
    assert client.post(url, headers=AGENT).status_code == 401  # an agent can never claw money back
    assert client.post("/api/decisions/dec_nope/refund", headers=ADMIN).status_code == 404
    open_order = world.buy("p_notebook")  # approved but not paid yet
    assert client.post(f"/api/decisions/{open_order.id}/refund", headers=ADMIN).status_code == 409
    assert client.post(url, headers=ADMIN, json={"note": "x" * 500}).status_code == 422
    ok = client.post(url, headers=ADMIN, json={"reviewer": "alex", "note": "mistake"})
    assert ok.status_code == 200 and ok.json()["status"] == "refunded" and ok.json()["refund_id"]
    assert client.get("/api/stats", headers=ADMIN).json()["refunded_usd"] == "12.00"
    # the agent sees the outcome in its own fixed vocabulary
    seen = client.get(f"/api/purchases/{paid.id}", headers=AGENT).json()
    assert seen["status"] == "refunded" and "refund_id" not in seen


def test_deny_endpoint_and_review_body_validation(client: TestClient, world: Any) -> None:
    held = world.buy("p_desk_lamp")  # waits for a human
    url = f"/api/decisions/{held.id}/deny"
    assert client.post(url, headers=ADMIN, json={"note": "x" * 500}).status_code == 422
    assert client.post(url, headers=ADMIN, json={"surprise": 1}).status_code == 422
    assert client.post(url, headers=ADMIN, json={"reviewer": "alex"}).json()["status"] == "human_denied"


def test_revoking_a_mandate_over_http(client: TestClient, world: Any) -> None:
    revoked = client.post(f"/api/mandates/{world.mandate.id}/revoke", headers=ADMIN)
    assert revoked.status_code == 200 and revoked.json()["active"] is False
    again = client.post(
        "/api/quotes", headers=AGENT, json={"mandate_id": world.mandate.id, "product_id": "p_usbc_cable"}
    )
    assert again.status_code == 409
    assert client.post("/api/mandates/mdt_nope/revoke", headers=ADMIN).status_code == 404


# --- input validation -------------------------------------------------------------------


def test_agent_cannot_name_a_price_or_a_payee(client: TestClient, world: Any) -> None:
    token = world.quote("p_usbc_cable")
    for extra in ({"price": "0.01"}, {"payee": "m_paypai"}, {"amount": "1.00"}):
        body = {"mandate_id": world.mandate.id, "quotes": [token], **extra}
        assert client.post("/api/purchases", headers=AGENT, json=body).status_code == 422
    quote_body = {"mandate_id": world.mandate.id, "product_id": "p_usbc_cable", "unit_price": "0.01"}
    assert client.post("/api/quotes", headers=AGENT, json=quote_body).status_code == 422


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/quotes", {"mandate_id": "", "product_id": "p"}),
        ("/api/quotes", {"mandate_id": "m", "product_id": "p", "quantity": 0}),
        ("/api/quotes", {"mandate_id": "m", "product_id": "p", "quantity": 51}),
        ("/api/purchases", {"mandate_id": "m", "quotes": []}),
        ("/api/purchases", {"mandate_id": "m", "quotes": ["q"] * 21}),
        ("/api/purchases", {"mandate_id": "m", "quotes": ["q"], "context": "x" * 20001}),
    ],
)
def test_bad_agent_input_is_a_422(client: TestClient, path: str, body: dict[str, Any]) -> None:
    assert client.post(path, headers=AGENT, json=body).status_code == 422


def test_mandate_creation_errors_are_clear(client: TestClient) -> None:
    bad_limits = {**catalog.DEMO_MANDATE, "per_order_limit": "500"}
    response = client.post("/api/mandates", headers=ADMIN, json=bad_limits)
    assert response.status_code == 422 and "per_order_limit" in response.text
    unknown = {**catalog.DEMO_MANDATE, "agent_can_set_prices": True}
    assert client.post("/api/mandates", headers=ADMIN, json=unknown).status_code == 422
    assert client.get("/api/decisions?limit=0", headers=ADMIN).status_code == 422


def test_unknown_product_and_decision_are_404(client: TestClient, world: Any) -> None:
    body = {"mandate_id": world.mandate.id, "product_id": "p_nope"}
    assert client.post("/api/quotes", headers=AGENT, json=body).status_code == 404
    assert client.get("/api/purchases/dec_nope", headers=AGENT).status_code == 404
    assert client.get("/api/decisions/dec_nope", headers=ADMIN).status_code == 404


def test_hostile_listings_are_hidden_unless_asked_for(client: TestClient) -> None:
    def ids(**params: Any) -> set[str]:
        found = client.get("/api/products", headers=AGENT, params={"q": "usb-c", **params}).json()
        return {p["product_id"] for p in found}

    assert ids().isdisjoint(catalog.HOSTILE) and "p_usbc_cable" in ids()
    assert "p_hub" in ids(hostile="true")


# --- what an agent can learn from a decision --------------------------------------------


def test_agent_view_never_echoes_attacker_text(client: TestClient, world: Any) -> None:
    mandate = world.new_mandate(allowed_merchants=["*"], allowed_categories=["office-supplies", "electronics"])
    attacks = [("p_stapler", 1), ("p_cheap_cable", 1), ("p_binder", 1), ("p_braided_cable", 1)]
    for product_id, qty in attacks:
        quote = world.quote(product_id, qty, mandate=mandate)
        raw = client.post(
            "/api/purchases", headers=AGENT, json={"mandate_id": mandate.id, "quotes": [quote]}
        )
        text = raw.text
        view = raw.json()
        assert view["outcome"] == "DENY", product_id
        for leaked in ("SYSTEM", "pre-approved", "confirmation", "C0ntoso", "Ignore", "payee", "evidence"):
            assert leaked not in text, (product_id, leaked)
        allowed = set(PUBLIC_REASONS.values()) | {
            "Listing or request text contains instructions aimed at AI agents",
            "Hidden or obfuscated text was found",
            "Flagged by a safety check",
        }
        assert set(view["reasons"]) <= allowed and view["reasons"], product_id


def test_admin_view_has_the_full_story(client: TestClient, world: Any) -> None:
    d = world.buy("p_stapler")
    full = client.get(f"/api/decisions/{d.id}", headers=ADMIN).json()
    assert {f["code"] for f in full["findings"]} >= {"INJECTION_PREAPPROVAL_CLAIM"}
    assert any("pre-approved" in f["evidence"] for f in full["findings"])
    listed = client.get("/api/decisions", headers=ADMIN).json()
    assert [row["id"] for row in listed] == [d.id]
    stats = client.get("/api/stats", headers=ADMIN).json()
    assert stats["decisions"] == 1 and stats["by_outcome"]["DENY"] == 1


def test_red_team_endpoint_runs_the_scorecard(client: TestClient) -> None:
    card = client.post("/api/redteam/run", headers=ADMIN).json()
    assert card["passed"] is True and card["counts"]["attacks"] == 20


# --- browser-facing pages and headers ---------------------------------------------------


def csp_directives(value: str) -> dict[str, str]:
    return {part.strip().split(" ", 1)[0]: part.strip() for part in value.split(";") if part.strip()}


def test_security_headers_everywhere(client: TestClient) -> None:
    for path in ("/api/health", "/", "/paypal/cancel", "/static/dashboard.js"):
        headers = client.get(path).headers
        assert headers["x-content-type-options"] == "nosniff", path
        assert headers["referrer-policy"] == "no-referrer", path
        assert headers["x-frame-options"] == "DENY", path
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_dashboard_csp_allows_only_our_own_scripts(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200 and "Tollgate" in response.text
    policy = csp_directives(response.headers["content-security-policy"])
    assert policy["script-src"] == "script-src 'self'"
    assert policy["frame-ancestors"] == "frame-ancestors 'none'"
    assert policy["object-src"] == "object-src 'none'" and policy["connect-src"] == "connect-src 'self'"
    assert "unsafe-eval" not in response.headers["content-security-policy"]
    # no inline scripts, so 'self' is enough; and nothing is loaded from a CDN
    assert not re.search(r"<script(?![^>]*\bsrc=)", response.text)
    assert not re.search(r"(?:src|href)=[\"']https?://", response.text)


def test_vendored_ag_grid_is_served_locally(client: TestClient) -> None:
    for path in ("/static/vendor/ag-grid/ag-grid-community.min.js", "/static/dashboard.js"):
        assert client.get(path).status_code == 200, path
    license_text = client.get("/static/vendor/ag-grid/LICENSE.txt").text
    assert "MIT" in license_text


def test_vendored_ag_charts_is_served_locally_and_loaded_before_the_dashboard(client: TestClient) -> None:
    script = client.get("/static/vendor/ag-charts/ag-charts-community.min.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]
    assert "agCharts" in script.text[:2000]  # the UMD wrapper exposes the global the dashboard uses
    license_text = client.get("/static/vendor/ag-charts/LICENSE.txt").text
    assert "MIT" in license_text and "AG GRID" in license_text
    page = client.get("/").text
    order = [page.index(name) for name in ("ag-grid-community.min.js", "ag-charts-community.min.js", "/static/dashboard.js")]
    assert order == sorted(order)  # both libraries must exist before the dashboard script runs


VENDORED = {  # path under static/vendor -> sha256. Update both together when you upgrade a library.
    "ag-grid/ag-grid-community.min.js": "b7b6654fc8dd387d370da3a3f84e2fd4ca9a1c95e2a0b9d3ac08ce858dcdea8f",  # 32.3.9
    "ag-charts/ag-charts-community.min.js": "bb55974410690aa28266f4512dd6091f9ae882f810e16287f8da5f2ad7223277",  # 14.3.0
}


@pytest.mark.parametrize("name", sorted(VENDORED))
def test_vendored_libraries_are_unmodified(client: TestClient, name: str) -> None:
    served = client.get(f"/static/vendor/{name}").content
    assert hashlib.sha256(served).hexdigest() == VENDORED[name], f"{name} changed; update VENDORED if on purpose"


def test_dashboard_script_never_writes_html(client: TestClient) -> None:
    source = client.get("/static/dashboard.js").text
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith(("*", "//", "/*"))
    )
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in code, sink


def test_pages_escape_what_they_show(client: TestClient) -> None:
    probe = urlquote('"><img src=x onerror=alert(1)>')
    for path in (f"/paypal/return?token={probe}", f"/mock/pay/{probe}"):
        response = client.get(path)
        assert response.status_code == 404 and "<img" not in response.text, path
        assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert client.get("/paypal/return?token=MOCK-NOPE").status_code == 404
    assert client.get("/mock/pay/MOCK-NOPE").status_code == 404
    assert client.post("/mock/pay/MOCK-NOPE/approve").status_code == 404


def test_mock_pages_are_labelled_and_not_pretending_to_be_paypal(client: TestClient, world: Any) -> None:
    d = world.buy("p_usbc_cable")
    page = client.get(f"/mock/pay/{d.paypal_order_id}").text
    assert "MOCK payment page" in page and "no real money" in page
    assert "paypal.com" not in page.lower()


# --- the PayPal webhook -----------------------------------------------------------------

VALID = {"paypal-transmission-sig": "mock-valid"}


def test_webhook_requires_a_valid_signature(client: TestClient, world: Any) -> None:
    d = world.buy("p_usbc_cable")
    world.payments.approve(d.paypal_order_id)
    event = {"event_type": "CHECKOUT.ORDER.APPROVED", "resource": {"id": d.paypal_order_id}}
    assert client.post("/webhooks/paypal", json=event).status_code == 400
    assert client.post("/webhooks/paypal", json=event, headers={"paypal-transmission-sig": "forged"}).status_code == 400
    assert world.engine.get_decision(d.id).status == "order_created"  # nothing happened

    ok = client.post("/webhooks/paypal", json=event, headers=VALID)
    assert ok.status_code == 200 and ok.json() == {"handled": True, "status": "captured"}


def test_webhook_rejects_garbage_even_when_signed(client: TestClient) -> None:
    assert client.post("/webhooks/paypal", content=b"not json", headers=VALID).status_code == 400
    assert client.post("/webhooks/paypal", content=b"[1, 2]", headers=VALID).status_code == 400
    too_big = b" " * (MAX_WEBHOOK_BYTES + 1)
    assert client.post("/webhooks/paypal", content=too_big, headers=VALID).status_code == 413
