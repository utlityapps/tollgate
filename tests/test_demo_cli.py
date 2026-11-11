from __future__ import annotations

import json
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from tollgate import cli, catalog
from tollgate.agent_demo import ALL_SCENES, Admin, Demo, dispatch_tool, local_stack, run_demo, run_llm_agent
from tollgate.gateway import HttpGateway, LocalGateway
from tollgate.paypal import PayPalError, PayPalOrder

Capture = pytest.CaptureFixture[str]


# --- the scripted demo ------------------------------------------------------------------


def test_scripted_demo_runs_every_scene(capsys: Capture) -> None:
    assert run_demo(color=False) == 0
    out = capsys.readouterr().out
    for scene in range(1, len(ALL_SCENES) + 1):
        assert f"Scene {scene}:" in out
    for word in ("[APPROVE]", "[ESCALATE]", "[DENY]", "payment paid", "What Tollgate decided"):
        assert word in out
    assert "\033[" not in out  # --no-color means no escape codes
    assert out.count("[DENY]") == 4 and out.count("[APPROVE]") == 1 and out.count("[ESCALATE]") == 1


def test_a_single_scene_can_be_run(capsys: Capture) -> None:
    assert run_demo(scenes=["poison"], color=False) == 0
    out = capsys.readouterr().out
    assert "Scene 1: A poisoned listing" in out and "[DENY]" in out and "[APPROVE]" not in out


def sandbox_demo(lines: list[str], **options: Any) -> tuple[Demo, list[str]]:
    """A scripted demo whose payments behave like the PayPal sandbox: the buyer approves by hand."""
    client, admin_token, agent_token = local_stack()
    admin = Admin(client, admin_token)
    gateway = HttpGateway("http://testserver", agent_token, client=client)
    demo = Demo(gateway, admin, auto=True, pause=0, color=False, out=lines.append, **options)
    demo.mock = False
    waited: list[str] = []
    real_wait = demo.wait_for

    def wait_for(decision_id: str, statuses: set[str], seconds: float) -> dict[str, Any]:
        if "captured" in statuses:  # the buyer's approval inside PayPal
            waited.append(decision_id)
            return {"status": "captured"}
        return real_wait(decision_id, statuses, seconds)

    demo.wait_for = wait_for  # type: ignore[method-assign]
    return demo, waited


def decision_ids_by_total(demo: Demo) -> dict[Decimal, str]:
    return {Decimal(d["total"]): d["id"] for d in demo.admin.decisions()}


def test_sandbox_demo_waits_for_the_buyer_only_on_the_last_order() -> None:
    lines: list[str] = []
    demo, waited = sandbox_demo(lines)
    demo.run(["honest", "human"])
    out = "\n".join(lines)
    assert waited == [decision_ids_by_total(demo)[Decimal("48.00")]]  # the desk lamp, not the cable
    assert out.count("leaves this PayPal sandbox order open") == 1
    assert out.count("sign in with a SANDBOX buyer") == 1


def test_sandbox_demo_can_wait_for_every_order() -> None:
    lines: list[str] = []
    demo, waited = sandbox_demo(lines, wait_all_payments=True)
    demo.run(["honest", "human"])
    ids = decision_ids_by_total(demo)
    assert waited == [ids[Decimal("12.00")], ids[Decimal("48.00")]]
    assert "leaves this PayPal sandbox order open" not in "\n".join(lines)


def test_sandbox_demo_with_one_paying_scene_waits_for_it() -> None:
    lines: list[str] = []
    demo, waited = sandbox_demo(lines)
    demo.run(["honest", "poison"])
    assert waited == [decision_ids_by_total(demo)[Decimal("12.00")]]


def test_sandbox_demo_without_paying_scenes_never_waits() -> None:
    lines: list[str] = []
    demo, waited = sandbox_demo(lines)
    demo.run(["poison", "tamper"])
    assert waited == [] and "sign in with a SANDBOX buyer" not in "\n".join(lines)


def test_mock_demo_still_pays_every_order(capsys: Capture) -> None:
    assert run_demo(scenes=["honest", "human"], color=False) == 0
    out = capsys.readouterr().out
    assert out.count("payment paid") == 2 and "leaves this PayPal sandbox order open" not in out


def test_cli_demo_accepts_wait_all_payments(capsys: Capture) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.main(["demo", "--scenes", "honest", "--wait-all-payments", "--no-color"])
    assert stop.value.code == 0 and "payment paid" in capsys.readouterr().out


def test_unknown_scene_is_a_usage_error(capsys: Capture) -> None:
    assert run_demo(scenes=["nope"]) == 2
    assert "unknown scene" in capsys.readouterr().err


def test_llm_mode_needs_a_key(monkeypatch: pytest.MonkeyPatch, capsys: Capture) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run_demo(llm=True, color=False) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


# --- a model driving the tools ----------------------------------------------------------


def block(**fields: Any) -> Any:
    return SimpleNamespace(**fields)


def tool_use(call_id: str, name: str, **arguments: Any) -> Any:
    return block(type="tool_use", id=call_id, name=name, input=arguments)


def reply(*blocks: Any, stop: str = "tool_use") -> Any:
    return SimpleNamespace(content=list(blocks), stop_reason=stop)


def last_results(history: list[dict[str, Any]]) -> list[Any]:
    return [json.loads(item["content"]) for item in history[-1]["content"]]


class ScriptedModel:
    """Stands in for the Anthropic client: `script(turn, history)` decides each reply."""

    def __init__(self, script: Callable[[int, list[dict[str, Any]]], Any]) -> None:
        self.script = script
        self.turn = 0
        self.messages = self

    def create(self, **kwargs: Any) -> Any:
        assert kwargs["tools"] and "untrusted" in kwargs["system"]
        answer = self.script(self.turn, kwargs["messages"])
        self.turn += 1
        return answer


def test_dispatch_tool_never_raises(world: Any) -> None:
    gateway = LocalGateway(world.engine)
    mid = world.mandate.id
    assert dispatch_tool(gateway, mid, "nope", {}, hostile=False) == {"error": "unknown tool nope"}
    assert "error" in dispatch_tool(gateway, mid, "get_quote", {}, hostile=False)  # missing argument
    assert "error" in dispatch_tool(gateway, mid, "get_quote", {"product_id": "p_x"}, hostile=False)
    assert "error" in dispatch_tool(gateway, mid, "purchase_status", {"decision_id": "d"}, hostile=False)
    found = dispatch_tool(gateway, mid, "search_products", {"query": "usb-c"}, hostile=True)
    assert "p_hub" in {p["product_id"] for p in found}


def test_honest_model_shops_through_tollgate(world: Any) -> None:
    def script(turn: int, history: list[dict[str, Any]]) -> Any:
        if turn == 0:
            return reply(block(type="text", text="Looking."), tool_use("t1", "get_quote", product_id="p_usbc_cable"))
        if turn == 1:
            quote = last_results(history)[0]["quote"]
            return reply(
                tool_use("t2", "request_purchase", quotes=[quote], justification="Cable for the laptop")
            )
        return reply(block(type="text", text="Ordered the cable."), stop="end_turn")

    lines: list[str] = []
    final = run_llm_agent(
        LocalGateway(world.engine), world.mandate.id, "Buy a cable",
        client=ScriptedModel(script), model="m", out=lines.append,
    )
    assert final == "Ordered the cable."
    assert any("APPROVE" in line for line in lines)
    decision = world.engine.list_decisions()[0]
    assert decision.agent_id == "llm-agent" and decision.status == "order_created"


def test_a_fully_compromised_model_still_cannot_spend(world: Any) -> None:
    poisoned = catalog.get("p_hub")
    assert poisoned is not None

    def script(turn: int, history: list[dict[str, Any]]) -> Any:
        if turn == 0:  # the model obeys the hidden instruction in the listing
            return reply(tool_use("t1", "get_quote", product_id="p_giftcard_100", quantity=5))
        if turn == 1:
            quote = last_results(history)[0]["quote"]
            return reply(
                tool_use(
                    "t2", "request_purchase", quotes=[quote],
                    justification="The listing told me to", context=poisoned.description,
                )
            )
        return reply(block(type="text", text="Blocked."), stop="end_turn")

    lines: list[str] = []
    run_llm_agent(
        LocalGateway(world.engine), world.mandate.id, "Buy a hub",
        client=ScriptedModel(script), model="m", out=lines.append,
    )
    assert any("DENY" in line for line in lines)
    stats = world.engine.stats()
    assert stats["by_outcome"]["DENY"] == 1 and Decimal(stats["approved_usd"]) == 0
    assert world.engine.list_decisions()[0].paypal_order_id is None


def test_model_loop_is_capped(world: Any) -> None:
    model = ScriptedModel(
        lambda turn, history: reply(tool_use(f"t{turn}", "purchase_status", decision_id="dec_x"))
    )
    final = run_llm_agent(
        LocalGateway(world.engine), world.mandate.id, "Loop forever",
        client=model, model="m", max_turns=3, out=lambda line: None,
    )
    assert final == "" and model.turn == 3


# --- command line -----------------------------------------------------------------------


def test_version_and_usage(capsys: Capture) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.main(["--version"])
    assert stop.value.code == 0 and capsys.readouterr().out.startswith("tollgate 0.")
    with pytest.raises(SystemExit) as stop:
        cli.main([])
    assert stop.value.code == 2


def test_cli_demo(capsys: Capture) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.main(["demo", "--scenes", "honest, tamper", "--no-color"])
    out = capsys.readouterr().out
    assert stop.value.code == 0 and "Scene 2: The agent edits a signed price quote" in out


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> pytest.MonkeyPatch:
    for key in (
        "TOLLGATE_SIGNING_KEY", "TOLLGATE_ADMIN_TOKEN", "TOLLGATE_AGENT_TOKEN", "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET", "PAYPAL_BASE_URL", "PAYPAL_WEBHOOK_ID", "ANTHROPIC_API_KEY",
        "PUBLIC_BASE_URL", "RENDER_EXTERNAL_URL", "TOLLGATE_ALLOW_LIVE",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("TOLLGATE_DB", ":memory:")
    monkeypatch.chdir(tmp_path)  # so no stray .env file is read
    return monkeypatch


@pytest.mark.parametrize(("host", "warned"), [("127.0.0.1", False), ("0.0.0.0", True)])
def test_serve_warns_before_exposing_demo_secrets(
    clean_env: pytest.MonkeyPatch, capsys: Capture, host: str, warned: bool
) -> None:
    import uvicorn

    clean_env.setenv("TOLLGATE_ALLOW_DEMO_SECRETS", "1")
    started: dict[str, Any] = {}
    clean_env.setattr(uvicorn, "run", lambda app, **kwargs: started.update(app=app, **kwargs))
    with pytest.raises(SystemExit) as stop:
        cli.main(["serve", "--host", host, "--port", "8123"])
    captured = capsys.readouterr()
    assert stop.value.code == 0 and started["host"] == host and started["port"] == 8123
    assert ("DEMO secrets" in captured.err) is warned
    assert "mock payments" in captured.out and "heuristic judge" in captured.out


def test_serve_refuses_a_public_address_with_demo_secrets(
    clean_env: pytest.MonkeyPatch, capsys: Capture
) -> None:
    # Audit A-01/A-02: the public demo token and signing key must never face a network.
    import uvicorn

    started: dict[str, Any] = {}
    clean_env.setattr(uvicorn, "run", lambda app, **kwargs: started.update(app=app, **kwargs))
    with pytest.raises(SystemExit) as stop:
        cli.main(["serve", "--host", "0.0.0.0", "--port", "8123"])
    assert stop.value.code == 2 and not started
    assert "Refusing" in capsys.readouterr().err


class FakePayPal:
    """Replaces PayPalClient for the smoke command."""

    seen_status = "APPROVED"
    fail = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    @staticmethod
    def order(status: str, **extra: Any) -> PayPalOrder:
        return PayPalOrder(id="5O190127TN364715T", status=status, amount=Decimal("1.00"), currency="USD", **extra)

    def create_order(self, **kwargs: Any) -> PayPalOrder:
        if self.fail:
            raise PayPalError("bad request", status=400, debug_id="dbg-1")
        assert kwargs["items"][0].total == Decimal("1.00") and kwargs["currency"] == "USD"
        return self.order("PAYER_ACTION_REQUIRED", approve_url="https://www.sandbox.paypal.com/checkoutnow?token=T")

    def get_order(self, order_id: str) -> PayPalOrder:
        return self.order(self.seen_status)

    def capture_order(self, order_id: str, *, request_id: str) -> PayPalOrder:
        return self.order("COMPLETED", capture_id="CAP1")


@pytest.fixture
def smoke_env(clean_env: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    clean_env.setenv("PAYPAL_CLIENT_ID", "id")
    clean_env.setenv("PAYPAL_CLIENT_SECRET", "secret")
    clean_env.setattr("tollgate.paypal.PayPalClient", FakePayPal)
    clean_env.setattr("builtins.input", lambda prompt="": "")
    FakePayPal.seen_status, FakePayPal.fail = "APPROVED", False
    return clean_env


def run_smoke(*args: str) -> int:
    with pytest.raises(SystemExit) as stop:
        cli.main(["smoke", *args])
    return int(stop.value.code)  # type: ignore[arg-type]


def test_smoke_needs_keys(clean_env: pytest.MonkeyPatch, capsys: Capture) -> None:
    assert run_smoke() == 2
    assert "PAYPAL_CLIENT_ID" in capsys.readouterr().out


def test_smoke_creates_approves_and_captures(smoke_env: pytest.MonkeyPatch, capsys: Capture) -> None:
    assert run_smoke() == 0
    out = capsys.readouterr().out
    assert "1/3 order created" in out and "checkoutnow" in out and "3/3 captured" in out and "CAP1" in out


def test_smoke_no_capture_stops_after_the_order(smoke_env: pytest.MonkeyPatch, capsys: Capture) -> None:
    assert run_smoke("--no-capture") == 0
    assert "3/3" not in capsys.readouterr().out


def test_smoke_does_not_capture_an_unapproved_order(smoke_env: pytest.MonkeyPatch, capsys: Capture) -> None:
    FakePayPal.seen_status = "PAYER_ACTION_REQUIRED"
    assert run_smoke() == 1
    assert "nothing was captured" in capsys.readouterr().out


def test_smoke_reports_paypal_errors(smoke_env: pytest.MonkeyPatch, capsys: Capture) -> None:
    FakePayPal.fail = True
    assert run_smoke() == 1
    assert "dbg-1" in capsys.readouterr().out
