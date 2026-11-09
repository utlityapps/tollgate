from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Callable

import httpx
import pytest

from tollgate.models import LineItem
from tollgate.paypal import MockPayPal, PayPalClient, PayPalError

ORDER = {
    "id": "5O190127TN364715T",
    "status": "PAYER_ACTION_REQUIRED",
    "purchase_units": [
        {"custom_id": "dec_1", "amount": {"currency_code": "USD", "value": "12.00"}}
    ],
    "links": [
        {"rel": "self", "href": "https://api-m.sandbox.paypal.com/v2/checkout/orders/5O190127TN364715T"},
        {"rel": "payer-action", "href": "https://www.sandbox.paypal.com/checkoutnow?token=5O190127TN364715T"},
    ],
}
CAPTURED = {
    **ORDER,
    "status": "COMPLETED",
    "purchase_units": [
        {
            "custom_id": "dec_1",
            "amount": {"currency_code": "USD", "value": "12.00"},
            "payments": {
                "captures": [
                    {"id": "CAP123", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": "12.00"}}
                ]
            },
        }
    ],
}
ITEM = LineItem(
    product_id="p_usbc_cable",
    name="USB-C cable",
    category="electronics",
    merchant_id="m_contoso",
    merchant_name="Contoso",
    unit_price=Decimal("12.00"),
    quantity=1,
)


class Recorder:
    def __init__(self, routes: dict[str, Callable[[httpx.Request], httpx.Response]]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.routes[request.url.path](request)

    def client(self, **kwargs: Any) -> PayPalClient:
        return PayPalClient(
            "client-id",
            "client-secret",
            transport=httpx.MockTransport(self),
            sleep=self.sleeps.append,
            **kwargs,
        )

    def count(self, path: str) -> int:
        return sum(r.url.path == path for r in self.requests)


def token_ok(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})


def create_order(client: PayPalClient) -> Any:
    return client.create_order(
        request_id="tg-create-dec_1",
        items=[ITEM],
        currency="USD",
        description="Tollgate order dec_1",
        custom_id="dec_1",
        return_url="http://localhost:8000/paypal/return",
        cancel_url="http://localhost:8000/paypal/cancel",
    )


def test_create_order_sends_the_right_request_and_parses_the_answer() -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/checkout/orders": lambda r: httpx.Response(201, json=ORDER),
        }
    )
    order = create_order(rec.client())
    assert order.id == "5O190127TN364715T"
    assert order.status == "PAYER_ACTION_REQUIRED"
    assert order.amount == Decimal("12.00") and order.custom_id == "dec_1"
    assert order.approve_url and "checkoutnow" in order.approve_url

    oauth, create = rec.requests
    assert oauth.headers["authorization"].startswith("Basic ")
    assert b"grant_type=client_credentials" in oauth.content
    assert create.headers["authorization"] == "Bearer tok"
    assert create.headers["paypal-request-id"] == "tg-create-dec_1"
    assert create.headers["prefer"] == "return=representation"
    body = json.loads(create.content)
    unit = body["purchase_units"][0]
    assert body["intent"] == "CAPTURE" and unit["custom_id"] == "dec_1"
    assert unit["amount"] == {
        "currency_code": "USD",
        "value": "12.00",
        "breakdown": {"item_total": {"currency_code": "USD", "value": "12.00"}},
    }
    assert unit["items"][0]["unit_amount"]["value"] == "12.00" and unit["items"][0]["quantity"] == "1"
    context = body["payment_source"]["paypal"]["experience_context"]
    assert context["return_url"].endswith("/paypal/return") and context["user_action"] == "PAY_NOW"


def test_access_token_is_cached() -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/checkout/orders": lambda r: httpx.Response(201, json=ORDER),
            "/v2/checkout/orders/5O190127TN364715T": lambda r: httpx.Response(200, json=ORDER),
        }
    )
    client = rec.client()
    create_order(client)
    client.get_order("5O190127TN364715T")
    assert rec.count("/v1/oauth2/token") == 1


def test_expired_token_is_refreshed_once() -> None:
    calls = {"orders": 0}

    def orders(request: httpx.Request) -> httpx.Response:
        calls["orders"] += 1
        if calls["orders"] == 1:
            return httpx.Response(401, json={"name": "AUTHENTICATION_FAILURE"})
        return httpx.Response(201, json=ORDER)

    rec = Recorder({"/v1/oauth2/token": token_ok, "/v2/checkout/orders": orders})
    assert create_order(rec.client()).id == "5O190127TN364715T"
    assert rec.count("/v1/oauth2/token") == 2


def test_transient_errors_are_retried_with_backoff() -> None:
    calls = {"n": 0}

    def orders(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] < 3 else httpx.Response(201, json=ORDER)

    rec = Recorder({"/v1/oauth2/token": token_ok, "/v2/checkout/orders": orders})
    assert create_order(rec.client()).status == "PAYER_ACTION_REQUIRED"
    assert calls["n"] == 3 and rec.sleeps == [0.4, 0.8]
    # every retry carried the same idempotency key
    keys = {r.headers["paypal-request-id"] for r in rec.requests if r.url.path == "/v2/checkout/orders"}
    assert keys == {"tg-create-dec_1"}


def test_gives_up_after_the_last_attempt() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    rec = Recorder({"/v1/oauth2/token": boom})
    with pytest.raises(PayPalError, match="could not reach PayPal"):
        create_order(rec.client(max_attempts=2))


def test_rejected_credentials() -> None:
    rec = Recorder({"/v1/oauth2/token": lambda r: httpx.Response(401, json={"error": "invalid_client"})})
    with pytest.raises(PayPalError, match="rejected the client credentials") as info:
        create_order(rec.client())
    assert "client-secret" not in str(info.value)


def test_api_errors_carry_status_and_debug_id() -> None:
    err = {"name": "UNPROCESSABLE_ENTITY", "message": "bad amount", "debug_id": "abc123"}
    rec = Recorder(
        {"/v1/oauth2/token": token_ok, "/v2/checkout/orders": lambda r: httpx.Response(422, json=err)}
    )
    with pytest.raises(PayPalError) as info:
        create_order(rec.client())
    assert info.value.status == 422 and info.value.debug_id == "abc123"
    assert "UNPROCESSABLE_ENTITY" in str(info.value)


def test_capture_parses_the_capture() -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/checkout/orders/5O190127TN364715T/capture": lambda r: httpx.Response(201, json=CAPTURED),
        }
    )
    done = rec.client().capture_order("5O190127TN364715T", request_id="tg-capture-dec_1")
    assert done.status == "COMPLETED" and done.capture_id == "CAP123"
    assert done.capture_amount == Decimal("12.00")
    capture = rec.requests[-1]
    assert capture.method == "POST" and capture.headers["paypal-request-id"] == "tg-capture-dec_1"
    assert capture.headers["content-type"].startswith("application/json")


REFUND = {
    "id": "1JU08902781691411",
    "status": "COMPLETED",
    "amount": {"currency_code": "USD", "value": "12.00"},
}


def test_refund_sends_the_right_request_and_parses_the_answer() -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/payments/captures/CAP123/refund": lambda r: httpx.Response(201, json=REFUND),
        }
    )
    refund = rec.client().refund_capture(
        "CAP123", request_id="tg-refund-dec_1-1", amount=Decimal("12"), currency="USD", note="Changed my mind"
    )
    assert (refund.id, refund.status, refund.amount, refund.currency) == (
        "1JU08902781691411", "COMPLETED", Decimal("12.00"), "USD"
    )
    sent = rec.requests[-1]
    assert sent.method == "POST" and sent.headers["paypal-request-id"] == "tg-refund-dec_1-1"
    assert sent.headers["prefer"] == "return=representation"
    assert json.loads(sent.content) == {
        "amount": {"currency_code": "USD", "value": "12.00"},
        "note_to_payer": "Changed my mind",
    }


def test_refund_without_a_note_and_with_a_minimal_response() -> None:
    minimal = {"id": "R1", "status": "PENDING"}  # PayPal's minimal representation has no amount
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/payments/captures/CAP123/refund": lambda r: httpx.Response(201, json=minimal),
        }
    )
    refund = rec.client().refund_capture("CAP123", request_id="r", amount=Decimal("12.00"), currency="USD")
    assert refund.status == "PENDING" and refund.amount == Decimal("12.00") and refund.currency == "USD"
    assert "note_to_payer" not in json.loads(rec.requests[-1].content)


def test_refund_errors_carry_status_and_debug_id() -> None:
    error = {"name": "CAPTURE_FULLY_REFUNDED", "message": "Already refunded.", "debug_id": "dbg-9"}
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v2/payments/captures/CAP123/refund": lambda r: httpx.Response(422, json=error),
        }
    )
    with pytest.raises(PayPalError, match="CAPTURE_FULLY_REFUNDED") as info:
        rec.client().refund_capture("CAP123", request_id="r", amount=Decimal("12"), currency="USD")
    assert info.value.status == 422 and info.value.debug_id == "dbg-9"


def test_capture_ids_are_validated_before_they_reach_a_url() -> None:
    rec = Recorder({})
    for bad in ("../../v1/oauth2/token", "abc", "CAP?x=1", ""):
        with pytest.raises(PayPalError, match="invalid PayPal capture id"):
            rec.client().refund_capture(bad, request_id="r", amount=Decimal("1"), currency="USD")
    assert rec.requests == []


def test_order_ids_are_validated_before_they_reach_a_url() -> None:
    rec = Recorder({})
    client = rec.client()
    for bad in ("../../v1/oauth2/token", "abc", "ORDER?x=1", ""):
        with pytest.raises(PayPalError, match="invalid PayPal order id"):
            client.get_order(bad)
        with pytest.raises(PayPalError, match="invalid PayPal order id"):
            client.capture_order(bad, request_id="r")
    assert rec.requests == []


WEBHOOK_HEADERS = {
    "PayPal-Auth-Algo": "SHA256withRSA",
    "PayPal-Cert-Url": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1",
    "PayPal-Transmission-Id": "tid-1",
    "PayPal-Transmission-Sig": "sig==",
    "PayPal-Transmission-Time": "2026-11-09T12:00:00Z",
}
EVENT = b'{"id":"WH-1","event_type":"CHECKOUT.ORDER.APPROVED","resource":{"id":"5O190127TN364715T"}}'


def test_webhook_verification_splices_the_raw_body() -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v1/notifications/verify-webhook-signature": lambda r: httpx.Response(
                200, json={"verification_status": "SUCCESS"}
            ),
        }
    )
    assert rec.client(webhook_id="WH-ID").verify_webhook(WEBHOOK_HEADERS, EVENT) is True
    sent = rec.requests[-1].content
    assert EVENT in sent  # verbatim, so the CRC check on PayPal's side still works
    body = json.loads(sent)
    assert body["webhook_id"] == "WH-ID" and body["transmission_id"] == "tid-1"


@pytest.mark.parametrize("status", ["FAILURE", "", "success"])
def test_webhook_failure_statuses(status: str) -> None:
    rec = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v1/notifications/verify-webhook-signature": lambda r: httpx.Response(
                200, json={"verification_status": status}
            ),
        }
    )
    assert rec.client(webhook_id="WH-ID").verify_webhook(WEBHOOK_HEADERS, EVENT) is False


def test_webhook_fails_closed() -> None:
    rec = Recorder({})
    assert rec.client().verify_webhook(WEBHOOK_HEADERS, EVENT) is False  # no webhook id
    client = rec.client(webhook_id="WH-ID")
    assert client.verify_webhook({}, EVENT) is False  # missing headers
    assert client.verify_webhook(WEBHOOK_HEADERS, b"not json") is False
    assert rec.requests == []
    err = Recorder(
        {
            "/v1/oauth2/token": token_ok,
            "/v1/notifications/verify-webhook-signature": lambda r: httpx.Response(500),
        }
    )
    assert err.client(webhook_id="WH-ID", max_attempts=1).verify_webhook(WEBHOOK_HEADERS, EVENT) is False


# --- the mock behaves like PayPal ---------------------------------------------------


def mock_order(mock: MockPayPal, request_id: str = "r1") -> Any:
    return mock.create_order(
        request_id=request_id,
        items=[ITEM],
        currency="USD",
        description="d",
        custom_id="dec_1",
        return_url="http://x/return",
        cancel_url="http://x/cancel",
    )


def test_mock_lifecycle_requires_buyer_approval_before_capture() -> None:
    mock = MockPayPal("http://testserver")
    order = mock_order(mock)
    assert order.status == "PAYER_ACTION_REQUIRED" and order.approve_url.endswith(order.id)
    with pytest.raises(PayPalError, match="ORDER_NOT_APPROVED"):
        mock.capture_order(order.id, request_id="c1")
    mock.approve(order.id)
    done = mock.capture_order(order.id, request_id="c1")
    assert done.status == "COMPLETED" and done.capture_id and done.approve_url is None
    assert mock.capture_order(order.id, request_id="c1").capture_id == done.capture_id


def test_mock_create_is_idempotent_and_unknown_orders_404() -> None:
    mock = MockPayPal()
    assert mock_order(mock, "same").id == mock_order(mock, "same").id
    assert mock_order(mock, "other").id != mock_order(mock, "same").id
    with pytest.raises(PayPalError) as info:
        mock.get_order("MOCK-NOPE")
    assert info.value.status == 404


def test_mock_cancel_and_tamper() -> None:
    mock = MockPayPal()
    order = mock_order(mock)
    mock.tamper_amount(order.id, "99.00")
    assert mock.get_order(order.id).amount == Decimal("99.00")
    assert mock.cancel(order.id).status == "VOIDED"
    with pytest.raises(PayPalError):
        mock.approve(order.id)


def mock_captured(mock: MockPayPal) -> Any:
    order = mock_order(mock)
    mock.approve(order.id)
    return mock.capture_order(order.id, request_id="c1")


def test_mock_refund_is_full_idempotent_and_only_once() -> None:
    mock = MockPayPal()
    done = mock_captured(mock)
    refund = mock.refund_capture(done.capture_id, request_id="rf1", amount=Decimal("12.00"), currency="USD")
    assert refund.status == "COMPLETED" and refund.amount == Decimal("12.00")
    assert mock.get_order(done.id).capture_status == "REFUNDED"
    again = mock.refund_capture(done.capture_id, request_id="rf1", amount=Decimal("12.00"), currency="USD")
    assert again.id == refund.id  # same request id, same refund
    with pytest.raises(PayPalError, match="CAPTURE_FULLY_REFUNDED"):
        mock.refund_capture(done.capture_id, request_id="rf2", amount=Decimal("12.00"), currency="USD")


def test_mock_refund_rejects_unknown_captures_and_wrong_amounts() -> None:
    mock = MockPayPal()
    done = mock_captured(mock)
    with pytest.raises(PayPalError) as info:
        mock.refund_capture("CAP-NOPE", request_id="rf1", amount=Decimal("12.00"), currency="USD")
    assert info.value.status == 404
    with pytest.raises(PayPalError, match="REFUND_AMOUNT_EXCEEDS_CAPTURE"):
        mock.refund_capture(done.capture_id, request_id="rf2", amount=Decimal("99.00"), currency="USD")
    with pytest.raises(PayPalError, match="REFUND_AMOUNT_EXCEEDS_CAPTURE"):
        mock.refund_capture(done.capture_id, request_id="rf3", amount=Decimal("12.00"), currency="EUR")
    assert mock.get_order(done.id).capture_status == "COMPLETED"  # nothing was refunded
