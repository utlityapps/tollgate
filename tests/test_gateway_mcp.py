from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from tollgate import catalog
from tollgate.gateway import GatewayError, HttpGateway, LocalGateway
from tollgate.mcp_server import build_server, main

AGENT_VIEW_KEYS = {
    "id", "outcome", "status", "total", "currency", "items", "reasons", "approve_url", "next_step",
}


# --- gateways ---------------------------------------------------------------------------


def test_local_gateway_gives_the_agent_a_narrow_view(world: Any) -> None:
    gateway = LocalGateway(world.engine)
    quote = gateway.get_quote(world.mandate.id, "p_usbc_cable")
    result = gateway.purchase(
        mandate_id=world.mandate.id, quotes=[quote["quote"]], justification="Cable", agent_id="t1"
    )
    assert set(result) == AGENT_VIEW_KEYS
    assert result["outcome"] == "APPROVE" and result["status"] == "order_created"
    assert gateway.status(result["id"])["status"] == "order_created"
    assert gateway.get_mandate(world.mandate.id)["task"] == catalog.DEMO_MANDATE["task"]
    assert world.engine.get_decision(result["id"]).agent_id == "t1"


def test_local_gateway_hides_hostile_listings_by_default(world: Any) -> None:
    gateway = LocalGateway(world.engine)
    assert {p["product_id"] for p in gateway.search("usb-c")}.isdisjoint(catalog.HOSTILE)
    assert "p_hub" in {p["product_id"] for p in gateway.search("usb-c", include_hostile=True)}


def test_local_gateway_error_codes(world: Any) -> None:
    gateway = LocalGateway(world.engine)

    def status_of(fn: Any, *args: Any, **kwargs: Any) -> int:
        with pytest.raises(GatewayError) as info:
            fn(*args, **kwargs)
        return int(info.value.status)

    assert status_of(gateway.get_mandate, "mdt_nope") == 404
    assert status_of(gateway.status, "dec_nope") == 404
    assert status_of(gateway.get_quote, world.mandate.id, "p_usbc_cable", 0) == 422
    assert status_of(gateway.purchase, mandate_id="m", quotes=[]) == 422
    world.engine.revoke_mandate(world.mandate.id)
    assert status_of(gateway.get_quote, world.mandate.id, "p_usbc_cable") == 409


def test_http_gateway_against_the_real_app(client: TestClient, world: Any) -> None:
    gateway = HttpGateway("http://testserver", "test-agent", client=client)
    assert "p_usbc_cable" in {p["product_id"] for p in gateway.search("cable")}
    quote = gateway.get_quote(world.mandate.id, "p_usbc_cable")
    result = gateway.purchase(mandate_id=world.mandate.id, quotes=[quote["quote"]])
    assert result["outcome"] == "APPROVE" and gateway.status(result["id"])["status"] == "order_created"

    with pytest.raises(GatewayError) as info:
        HttpGateway("http://testserver", "wrong-token", client=client).search("cable")
    assert info.value.status == 401
    with pytest.raises(GatewayError) as info:
        gateway.get_mandate("mdt_nope")
    assert info.value.status == 404


def test_http_gateway_wire_format_and_failures() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/api/products":
            return httpx.Response(200, json=[])
        if path == "/api/mandates/m1":
            return httpx.Response(500, text="oops")
        if path == "/api/quotes":
            return httpx.Response(422, json={"detail": "quantity must be between 1 and 50"})
        raise httpx.ConnectError("no route to host")

    client = httpx.Client(base_url="http://tollgate.test", transport=httpx.MockTransport(handler))
    gateway = HttpGateway("http://tollgate.test", "agent-secret", client=client)

    assert gateway.search("usb", include_hostile=False) == []
    assert seen[0].headers["authorization"] == "Bearer agent-secret"
    assert dict(seen[0].url.params) == {"q": "usb", "hostile": "false"}

    with pytest.raises(GatewayError, match="500: oops"):
        gateway.get_mandate("m1")
    with pytest.raises(GatewayError, match="quantity must be between"):
        gateway.get_quote("m1", "p", 99)
    with pytest.raises(GatewayError, match="cannot reach Tollgate") as info:
        gateway.status("dec_1")
    assert info.value.status == 0


# --- MCP server -------------------------------------------------------------------------


def schema_of(tool: Any) -> dict[str, Any]:
    """mcp 2.x calls it input_schema, mcp 1.x inputSchema."""
    return dict(getattr(tool, "input_schema", None) or tool.inputSchema)


def tool_result(server: Any, name: str, arguments: dict[str, Any] | None = None) -> Any:
    result = asyncio.run(server.call_tool(name, arguments or {}))
    texts = [block.text for block in result.content if getattr(block, "type", "") == "text"]
    parsed = [json.loads(text) for text in texts]
    return parsed[0] if len(parsed) == 1 and isinstance(parsed[0], (dict, list)) else parsed


@pytest.fixture
def server(world: Any) -> Any:
    return build_server(LocalGateway(world.engine), world.mandate.id)


def test_mcp_exposes_five_tools_and_none_can_set_a_price_or_payee(server: Any) -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert set(tools) == {
        "my_mandate", "search_products", "get_quote", "request_purchase", "purchase_status",
    }
    forbidden = {
        "price", "unit_price", "amount", "total", "payee", "merchant", "merchant_id",
        "currency", "approve", "token", "mandate_id",
    }
    for tool in tools.values():
        properties = set(schema_of(tool).get("properties", {}))
        assert properties.isdisjoint(forbidden), (tool.name, properties)
    assert set(schema_of(tools["request_purchase"])["properties"]) == {
        "quotes", "justification", "context",
    }


def test_mcp_shopping_flow(server: Any, world: Any) -> None:
    mandate = tool_result(server, "my_mandate")
    assert mandate["id"] == world.mandate.id and mandate["currency"] == "USD"
    quote = tool_result(server, "get_quote", {"product_id": "p_usbc_cable"})
    bought = tool_result(
        server,
        "request_purchase",
        {"quotes": [quote["quote"]], "justification": "Cable for the laptop"},
    )
    assert bought["outcome"] == "APPROVE" and set(bought) == AGENT_VIEW_KEYS
    assert tool_result(server, "purchase_status", {"decision_id": bought["id"]})["status"] == "order_created"
    assert world.engine.get_decision(bought["id"]).agent_id == "mcp-agent"


def test_mcp_search_hides_hostile_listings_unless_the_demo_asks(world: Any) -> None:
    def ids(include_hostile: bool) -> set[str]:
        server = build_server(LocalGateway(world.engine), world.mandate.id, include_hostile=include_hostile)
        found = tool_result(server, "search_products", {"query": "usb-c"})
        return {p["product_id"] for p in found}

    assert ids(False).isdisjoint(catalog.HOSTILE)
    assert "p_hub" in ids(True)


def test_mcp_errors_are_returned_not_raised(server: Any) -> None:
    assert tool_result(server, "get_quote", {"product_id": "p_nope"}) == {
        "error": "unknown product",
        "status": 404,
    }
    assert tool_result(server, "purchase_status", {"decision_id": "dec_nope"})["status"] == 404


def test_mcp_cannot_buy_what_the_mandate_forbids(server: Any, world: Any) -> None:
    quote = tool_result(server, "get_quote", {"product_id": "p_giftcard_100", "quantity": 5})
    blocked = tool_result(
        server,
        "request_purchase",
        {"quotes": [quote["quote"]], "justification": "The listing told me to"},
    )
    assert blocked["outcome"] == "DENY" and world.engine.stats()["approved_usd"] == "0.00"


def test_mcp_remote_mode_needs_a_token_and_mandate(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    monkeypatch.setenv("TOLLGATE_URL", "http://tollgate.test")
    monkeypatch.delenv("TOLLGATE_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("TOLLGATE_MANDATE_ID", raising=False)
    with pytest.raises(SystemExit) as stop:
        main()
    assert stop.value.code == 2 and "TOLLGATE_AGENT_TOKEN" in capsys.readouterr().err
