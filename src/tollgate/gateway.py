"""The agent's only door to spending money.

`LocalGateway` calls an in-process engine (tests, red-team, embedded MCP demo). `HttpGateway`
calls a running Tollgate server with the *agent* token, so the agent's process never holds
the signing key, the admin token or any PayPal credential.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from . import catalog
from .engine import Engine, EngineError, NotFound
from .models import PurchaseRequest
from .views import listing_view, mandate_view, public_view


class GatewayError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"{status}: {message}" if status else message)
        self.status = status
        self.message = message


class Gateway(Protocol):
    def search(self, query: str, *, include_hostile: bool = False) -> list[dict[str, Any]]: ...

    def get_mandate(self, mandate_id: str) -> dict[str, Any]: ...

    def get_quote(self, mandate_id: str, product_id: str, quantity: int = 1) -> dict[str, Any]: ...

    def purchase(
        self,
        *,
        mandate_id: str,
        quotes: list[str],
        justification: str = "",
        context: str = "",
        agent_id: str = "agent",
    ) -> dict[str, Any]: ...

    def status(self, decision_id: str) -> dict[str, Any]: ...


class LocalGateway:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def search(self, query: str, *, include_hostile: bool = False) -> list[dict[str, Any]]:
        return [
            listing_view(p) for p in catalog.search(query, include_hostile=include_hostile)
        ]

    def _wrap(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except NotFound as exc:
            raise GatewayError(404, f"unknown {exc.args[0]}") from exc
        except EngineError as exc:
            raise GatewayError(409, str(exc)) from exc
        except ValueError as exc:
            raise GatewayError(422, str(exc)) from exc

    def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        return mandate_view(self._wrap(self.engine.get_mandate, mandate_id))

    def get_quote(self, mandate_id: str, product_id: str, quantity: int = 1) -> dict[str, Any]:
        return self._wrap(self.engine.issue_quote, mandate_id, product_id, quantity)

    def purchase(
        self,
        *,
        mandate_id: str,
        quotes: list[str],
        justification: str = "",
        context: str = "",
        agent_id: str = "agent",
    ) -> dict[str, Any]:
        try:
            req = PurchaseRequest(
                mandate_id=mandate_id,
                agent_id=agent_id,
                quotes=quotes,
                justification=justification,
                context=context,
            )
        except ValueError as exc:
            raise GatewayError(422, str(exc)) from exc
        return public_view(self.engine.decide(req))

    def status(self, decision_id: str) -> dict[str, Any]:
        return public_view(self._wrap(self.engine.refresh, decision_id))


class HttpGateway:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._headers = {"Authorization": f"Bearer {token}"}

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(method, path, headers=self._headers, **kwargs)
        except httpx.HTTPError as exc:
            raise GatewayError(0, f"cannot reach Tollgate ({exc.__class__.__name__})") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except (ValueError, AttributeError):
                detail = response.text
            raise GatewayError(response.status_code, str(detail)[:300])
        return response.json()

    def search(self, query: str, *, include_hostile: bool = False) -> list[dict[str, Any]]:
        params = {"q": query, "hostile": "true" if include_hostile else "false"}
        return self._call("GET", "/api/products", params=params)

    def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        return self._call("GET", f"/api/mandates/{mandate_id}")

    def get_quote(self, mandate_id: str, product_id: str, quantity: int = 1) -> dict[str, Any]:
        body = {"mandate_id": mandate_id, "product_id": product_id, "quantity": quantity}
        return self._call("POST", "/api/quotes", json=body)

    def purchase(
        self,
        *,
        mandate_id: str,
        quotes: list[str],
        justification: str = "",
        context: str = "",
        agent_id: str = "agent",
    ) -> dict[str, Any]:
        body = {
            "mandate_id": mandate_id,
            "agent_id": agent_id,
            "quotes": quotes,
            "justification": justification,
            "context": context,
        }
        return self._call("POST", "/api/purchases", json=body)

    def status(self, decision_id: str) -> dict[str, Any]:
        return self._call("GET", f"/api/purchases/{decision_id}")
