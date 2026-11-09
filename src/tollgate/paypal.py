"""PayPal Orders v2 client (sandbox) and an in-memory mock with the same interface.

Tollgate only talks to the PayPal *sandbox* unless TOLLGATE_ALLOW_LIVE=1 is set. Every
state-changing call carries a PayPal-Request-Id, so a retry after a timeout cannot create
a second order or capture twice.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

import httpx

from .models import LineItem, money

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_ORDER_ID = re.compile(r"^[A-Za-z0-9_-]{5,64}$")


class PayPalError(RuntimeError):
    """PayPal (or the network) refused or failed. The message never contains credentials."""

    def __init__(
        self, message: str, *, status: int | None = None, debug_id: str | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.debug_id = debug_id


def _amount(value: Any) -> Decimal:
    try:
        return money(value)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise PayPalError("PayPal returned an amount that could not be parsed") from exc


@dataclass(frozen=True)
class PayPalOrder:
    id: str
    status: str
    amount: Decimal
    currency: str
    custom_id: str = ""
    approve_url: str | None = None
    capture_id: str | None = None
    capture_status: str | None = None
    capture_amount: Decimal | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> "PayPalOrder":
        units = data.get("purchase_units") or [{}]
        unit = units[0] or {}
        amount = unit.get("amount") or {}
        captures = (unit.get("payments") or {}).get("captures") or []
        capture = captures[0] if captures else {}
        capture_amount = capture.get("amount") or {}
        approve = next(
            (
                link.get("href")
                for link in data.get("links") or []
                if link.get("rel") in ("payer-action", "approve")
            ),
            None,
        )
        return cls(
            id=str(data.get("id", "")),
            status=str(data.get("status", "")),
            amount=_amount(amount.get("value", "0")),
            currency=str(amount.get("currency_code", "")),
            custom_id=str(unit.get("custom_id", "")),
            approve_url=approve,
            capture_id=capture.get("id"),
            capture_status=capture.get("status"),
            capture_amount=_amount(capture_amount["value"]) if "value" in capture_amount else None,
            raw=dict(data),
        )


class PaymentsBackend(Protocol):
    name: str

    def create_order(
        self,
        *,
        request_id: str,
        items: Sequence[LineItem],
        currency: str,
        description: str,
        custom_id: str,
        return_url: str,
        cancel_url: str,
    ) -> PayPalOrder: ...

    def get_order(self, order_id: str) -> PayPalOrder: ...

    def capture_order(self, order_id: str, *, request_id: str) -> PayPalOrder: ...

    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> bool: ...


class PayPalClient:
    """Thin, retrying client for the PayPal Orders v2 REST API."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        base_url: str = "https://api-m.sandbox.paypal.com",
        webhook_id: str = "",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 20.0,
        max_attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.name = "paypal-sandbox" if "sandbox" in base_url else "paypal-live"
        self._client_id = client_id
        self._client_secret = client_secret
        self._webhook_id = webhook_id
        self._http = httpx.Client(base_url=base_url, timeout=timeout, transport=transport)
        self._max_attempts = max(1, max_attempts)
        self._sleep = sleep
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_expiry = 0.0

    # --- transport -------------------------------------------------------------------
    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(1, self._max_attempts + 1):
            last = attempt == self._max_attempts
            try:
                response = self._http.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if last:
                    raise PayPalError(f"could not reach PayPal ({exc.__class__.__name__})") from exc
                self._sleep(0.4 * 2 ** (attempt - 1))
                continue
            if response.status_code in RETRY_STATUSES and not last:
                self._sleep(0.4 * 2 ** (attempt - 1))
                continue
            return response
        raise PayPalError("PayPal request failed")  # pragma: no cover

    def _access_token(self, *, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.time() < self._token_expiry - 60:
                return self._token
            response = self._send(
                "POST",
                "/v1/oauth2/token",
                auth=(self._client_id, self._client_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            )
            if response.status_code != 200:
                raise PayPalError(
                    f"PayPal rejected the client credentials ({response.status_code})",
                    status=response.status_code,
                )
            try:
                body = response.json()
                token = str(body["access_token"])
                expires = float(body.get("expires_in", 300))
            except (ValueError, KeyError, TypeError) as exc:
                raise PayPalError("PayPal returned an unexpected OAuth response") from exc
            self._token, self._token_expiry = token, time.time() + expires
            return token

    @staticmethod
    def _parse(response: httpx.Response) -> dict[str, Any]:
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if response.status_code >= 400:
            name = data.get("name") or "ERROR"
            message = data.get("message") or response.reason_phrase
            raise PayPalError(
                f"PayPal {response.status_code} {name}: {message}",
                status=response.status_code,
                debug_id=data.get("debug_id") or response.headers.get("paypal-debug-id"),
            )
        return data

    def _api(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        request_id: str | None = None,
        prefer_representation: bool = False,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if request_id:
            headers["PayPal-Request-Id"] = request_id[:108]
        if prefer_representation:
            headers["Prefer"] = "return=representation"
        if content is not None:
            headers["Content-Type"] = "application/json"
        response: httpx.Response | None = None
        for attempt in (1, 2):
            headers["Authorization"] = f"Bearer {self._access_token(force=attempt == 2)}"
            response = self._send(method, path, headers=headers, json=json_body, content=content)
            if response.status_code == 401 and attempt == 1:
                continue  # token expired early; fetch a new one and retry once
            break
        assert response is not None
        return self._parse(response)

    # --- Orders v2 -------------------------------------------------------------------
    def create_order(
        self,
        *,
        request_id: str,
        items: Sequence[LineItem],
        currency: str,
        description: str,
        custom_id: str,
        return_url: str,
        cancel_url: str,
    ) -> PayPalOrder:
        total = money(sum((i.total for i in items), Decimal("0")))
        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": custom_id[:256],
                    "custom_id": custom_id[:127],
                    "description": description[:127],
                    "amount": {
                        "currency_code": currency,
                        "value": str(total),
                        "breakdown": {"item_total": {"currency_code": currency, "value": str(total)}},
                    },
                    "items": [
                        {
                            "name": item.name[:127],
                            "sku": item.product_id[:127],
                            "quantity": str(item.quantity),
                            "unit_amount": {
                                "currency_code": currency,
                                "value": str(money(item.unit_price)),
                            },
                        }
                        for item in items
                    ],
                }
            ],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "brand_name": "Tollgate demo",
                        "user_action": "PAY_NOW",
                        "shipping_preference": "NO_SHIPPING",
                        "payment_method_preference": "IMMEDIATE_PAYMENT_REQUIRED",
                        "return_url": return_url,
                        "cancel_url": cancel_url,
                    }
                }
            },
        }
        data = self._api(
            "POST",
            "/v2/checkout/orders",
            json_body=body,
            request_id=request_id,
            prefer_representation=True,
        )
        return PayPalOrder.from_api(data)

    def get_order(self, order_id: str) -> PayPalOrder:
        if not _ORDER_ID.match(order_id):
            raise PayPalError("invalid PayPal order id")
        return PayPalOrder.from_api(self._api("GET", f"/v2/checkout/orders/{order_id}"))

    def capture_order(self, order_id: str, *, request_id: str) -> PayPalOrder:
        if not _ORDER_ID.match(order_id):
            raise PayPalError("invalid PayPal order id")
        data = self._api(
            "POST",
            f"/v2/checkout/orders/{order_id}/capture",
            json_body={},
            request_id=request_id,
            prefer_representation=True,
        )
        return PayPalOrder.from_api(data)

    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> bool:
        """Ask PayPal whether a webhook is genuine. Fails closed on anything unexpected."""
        if not self._webhook_id:
            return False
        h = {k.lower(): v for k, v in headers.items()}
        needed = (
            "paypal-auth-algo",
            "paypal-cert-url",
            "paypal-transmission-id",
            "paypal-transmission-sig",
            "paypal-transmission-time",
        )
        if any(k not in h for k in needed):
            return False
        try:
            event_text = body.decode("utf-8")
            json.loads(event_text)
        except (UnicodeDecodeError, ValueError):
            return False
        dumps = json.dumps
        # The webhook body is spliced in verbatim: re-serialising it would break the CRC check.
        payload = (
            '{"auth_algo":%s,"cert_url":%s,"transmission_id":%s,"transmission_sig":%s,'
            '"transmission_time":%s,"webhook_id":%s,"webhook_event":%s}'
            % (
                dumps(h["paypal-auth-algo"]),
                dumps(h["paypal-cert-url"]),
                dumps(h["paypal-transmission-id"]),
                dumps(h["paypal-transmission-sig"]),
                dumps(h["paypal-transmission-time"]),
                dumps(self._webhook_id),
                event_text,
            )
        )
        try:
            data = self._api(
                "POST",
                "/v1/notifications/verify-webhook-signature",
                content=payload.encode("utf-8"),
            )
        except PayPalError:
            return False
        return data.get("verification_status") == "SUCCESS"


class MockPayPal:
    """In-memory stand-in for PayPal so the whole project runs with no keys.

    It follows the real lifecycle: PAYER_ACTION_REQUIRED -> APPROVED -> COMPLETED, and a
    capture before the buyer approves is refused, just like PayPal does.
    """

    name = "mock"

    def __init__(self, public_base_url: str = "http://localhost:8000") -> None:
        self._base = public_base_url.rstrip("/")
        self._orders: dict[str, dict[str, Any]] = {}
        self._by_request: dict[str, str] = {}
        self._lock = threading.RLock()

    def _view(self, order_id: str) -> PayPalOrder:
        o = self._orders[order_id]
        waiting = o["status"] in ("PAYER_ACTION_REQUIRED", "CREATED")
        done = o["capture_id"] is not None
        return PayPalOrder(
            id=order_id,
            status=o["status"],
            amount=o["amount"],
            currency=o["currency"],
            custom_id=o["custom_id"],
            approve_url=f"{self._base}/mock/pay/{order_id}" if waiting else None,
            capture_id=o["capture_id"],
            capture_status="COMPLETED" if done else None,
            capture_amount=o["amount"] if done else None,
        )

    def _get(self, order_id: str) -> dict[str, Any]:
        if order_id not in self._orders:
            raise PayPalError("RESOURCE_NOT_FOUND: no such order", status=404)
        return self._orders[order_id]

    def create_order(
        self,
        *,
        request_id: str,
        items: Sequence[LineItem],
        currency: str,
        description: str,
        custom_id: str,
        return_url: str,
        cancel_url: str,
    ) -> PayPalOrder:
        with self._lock:
            existing = self._by_request.get(request_id)
            if existing:  # idempotent, like PayPal-Request-Id
                return self._view(existing)
            total = money(sum((i.total for i in items), Decimal("0")))
            order_id = "MOCK-" + secrets.token_hex(5).upper()
            self._orders[order_id] = {
                "status": "PAYER_ACTION_REQUIRED",
                "amount": total,
                "currency": currency,
                "custom_id": custom_id,
                "capture_id": None,
            }
            self._by_request[request_id] = order_id
            return self._view(order_id)

    def get_order(self, order_id: str) -> PayPalOrder:
        with self._lock:
            self._get(order_id)
            return self._view(order_id)

    def approve(self, order_id: str) -> PayPalOrder:
        """The buyer clicks 'Approve' on the payment page."""
        with self._lock:
            order = self._get(order_id)
            if order["status"] not in ("PAYER_ACTION_REQUIRED", "CREATED", "APPROVED"):
                raise PayPalError(f"ORDER_NOT_APPROVABLE: order is {order['status']}", status=422)
            order["status"] = "APPROVED"
            return self._view(order_id)

    def cancel(self, order_id: str) -> PayPalOrder:
        with self._lock:
            order = self._get(order_id)
            if order["status"] in ("PAYER_ACTION_REQUIRED", "CREATED"):
                order["status"] = "VOIDED"
            return self._view(order_id)

    def capture_order(self, order_id: str, *, request_id: str) -> PayPalOrder:
        with self._lock:
            order = self._get(order_id)
            if order["status"] == "COMPLETED":
                return self._view(order_id)  # idempotent
            if order["status"] != "APPROVED":
                raise PayPalError(
                    "ORDER_NOT_APPROVED: the buyer has not approved this order", status=422
                )
            order["status"] = "COMPLETED"
            order["capture_id"] = "CAP-" + secrets.token_hex(5).upper()
            return self._view(order_id)

    def tamper_amount(self, order_id: str, amount: Any) -> None:
        """Test hook: change an order's amount behind Tollgate's back."""
        with self._lock:
            self._get(order_id)["amount"] = money(amount)

    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> bool:
        return {k.lower(): v for k, v in headers.items()}.get("paypal-transmission-sig") == "mock-valid"
