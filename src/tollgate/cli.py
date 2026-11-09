"""Command line: serve the app, run the red team, run the demo agent, smoke-test PayPal."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections.abc import Sequence
from decimal import Decimal

from . import __version__


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app
    from .config import Settings

    settings = Settings.from_env()
    if settings.using_demo_secrets and args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: binding to a public address with DEMO secrets. Set TOLLGATE_SIGNING_KEY, "
            "TOLLGATE_ADMIN_TOKEN and TOLLGATE_AGENT_TOKEN first.",
            file=sys.stderr,
        )
    mode = "PayPal sandbox" if settings.paypal_configured else "mock payments (no PayPal keys set)"
    judge = "LLM + heuristic judge" if settings.llm_configured else "heuristic judge"
    print(f"Tollgate {__version__}: {mode}, {judge}")
    print(f"Dashboard: http://{args.host}:{args.port}/")
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level="info")
    return 0


def _redteam(args: argparse.Namespace) -> int:
    from .redteam import run_scorecard

    scorecard = run_scorecard()
    print(json.dumps(scorecard.to_dict(), indent=2) if args.json else scorecard.render_text())
    return 0 if scorecard.passed else 1


def _demo(args: argparse.Namespace) -> int:
    from .agent_demo import run_demo

    scenes = [s.strip() for s in args.scenes.split(",") if s.strip()] if args.scenes else None
    return run_demo(
        url=args.url,
        admin_token=args.admin_token,
        agent_token=args.agent_token,
        scenes=scenes,
        llm=args.llm,
        auto=args.auto,
        pause=args.pause,
        color=False if args.no_color else None,
    )


def _smoke(args: argparse.Namespace) -> int:
    """Talk to the real PayPal sandbox once: create a $1.00 order, approve it, capture it."""
    from .config import Settings
    from .models import LineItem
    from .paypal import PayPalClient, PayPalError

    settings = Settings.from_env()
    if not settings.paypal_configured:
        print("Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (sandbox app credentials) in .env first.")
        return 2
    client = PayPalClient(
        settings.paypal_client_id,
        settings.paypal_client_secret,
        base_url=settings.paypal_base_url,
        webhook_id=settings.paypal_webhook_id,
    )
    item = LineItem(
        product_id="smoke-test",
        name="Tollgate smoke test",
        category="test",
        merchant_id="m_test",
        merchant_name="Tollgate",
        unit_price=Decimal("1.00"),
        quantity=1,
    )
    tag = secrets.token_hex(4)
    try:
        order = client.create_order(
            request_id=f"tg-smoke-{tag}",
            items=[item],
            currency="USD",
            description="Tollgate smoke test",
            custom_id=f"smoke-{tag}",
            return_url=f"{settings.public_base_url}/paypal/return",
            cancel_url=f"{settings.public_base_url}/paypal/cancel",
        )
        print(f"1/3 order created: {order.id} status={order.status} amount={order.amount} {order.currency}")
        print(f"    approve (sandbox buyer account): {order.approve_url}")
        if args.no_capture:
            return 0
        input("2/3 approve the order in your browser, then press Enter... ")
        seen = client.get_order(order.id)
        print(f"    order status: {seen.status}")
        if seen.status != "APPROVED":
            print("    not approved yet, so nothing was captured.")
            return 1
        done = client.capture_order(order.id, request_id=f"tg-smoke-capture-{tag}")
        print(f"3/3 captured: status={done.status} capture_id={done.capture_id}")
        return 0 if done.status == "COMPLETED" else 1
    except PayPalError as exc:
        print(f"PayPal error: {exc} (debug id: {exc.debug_id or 'n/a'})")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tollgate", description="A checkout firewall for AI shopping agents."
    )
    parser.add_argument("--version", action="version", version=f"tollgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API and dashboard")
    serve.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    serve.set_defaults(func=_serve)

    redteam = sub.add_parser("redteam", help="replay the attack suite and print a scorecard")
    redteam.add_argument("--json", action="store_true", help="print the scorecard as JSON")
    redteam.set_defaults(func=_redteam)

    demo = sub.add_parser("demo", help="run the demo agent")
    demo.add_argument("--url", help="a running Tollgate server (omit to use a private in-process one)")
    demo.add_argument("--admin-token", default="")
    demo.add_argument("--agent-token", default="")
    demo.add_argument("--scenes", help="comma list: honest,poison,invisible,tamper,human,lookalike")
    demo.add_argument("--llm", action="store_true", help="use a real Claude agent (needs ANTHROPIC_API_KEY)")
    demo.add_argument("--auto", action="store_true", help="approve held orders automatically")
    demo.add_argument("--pause", type=float, default=0.0, help="seconds between scenes (for recording)")
    demo.add_argument("--no-color", action="store_true")
    demo.set_defaults(func=_demo)

    smoke = sub.add_parser("smoke", help="check your PayPal sandbox keys with a real $1.00 order")
    smoke.add_argument("--no-capture", action="store_true", help="create the order but do not capture")
    smoke.set_defaults(func=_smoke)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    main()
