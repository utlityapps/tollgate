"""Runtime settings, read from environment variables (and an optional .env file)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

DEFAULT_SIGNING_KEY = "dev-signing-key-change-me"
DEMO_ADMIN_TOKEN = "demo-admin"
DEMO_AGENT_TOKEN = "demo-agent"
SANDBOX_HOST = "api-m.sandbox.paypal.com"


@dataclass(frozen=True)
class Settings:
    db_path: str = "tollgate.db"
    signing_key: str = DEFAULT_SIGNING_KEY
    admin_token: str = DEMO_ADMIN_TOKEN
    agent_token: str = DEMO_AGENT_TOKEN
    paypal_client_id: str = ""
    paypal_client_secret: str = ""
    paypal_base_url: str = f"https://{SANDBOX_HOST}"
    paypal_webhook_id: str = ""
    paypal_merchant_id: str = ""
    public_base_url: str = "http://localhost:8000"
    anthropic_api_key: str = ""
    judge_model: str = "claude-haiku-5-5"
    agent_model: str = "claude-sonnet-5-5"
    quote_ttl_seconds: int = 900

    @property
    def paypal_configured(self) -> bool:
        return bool(self.paypal_client_id and self.paypal_client_secret)

    @property
    def llm_configured(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def using_demo_secrets(self) -> bool:
        return (
            self.signing_key == DEFAULT_SIGNING_KEY
            or self.admin_token == DEMO_ADMIN_TOKEN
            or self.agent_token == DEMO_AGENT_TOKEN
        )

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, load_env_file: bool = True
    ) -> "Settings":
        if env is None:
            if load_env_file:
                load_dotenv()
            env = os.environ

        def get(key: str, default: str = "") -> str:
            return (env.get(key) or default).strip()

        base_url = get("PAYPAL_BASE_URL", f"https://{SANDBOX_HOST}").rstrip("/")
        if urlparse(base_url).hostname != SANDBOX_HOST and get("TOLLGATE_ALLOW_LIVE") != "1":
            raise ValueError(
                "Refusing to use a non-sandbox PayPal URL. Tollgate is sandbox-only; "
                "set TOLLGATE_ALLOW_LIVE=1 to override at your own risk."
            )
        public_url = (
            get("PUBLIC_BASE_URL") or get("RENDER_EXTERNAL_URL") or "http://localhost:8000"
        ).rstrip("/")
        return cls(
            db_path=get("TOLLGATE_DB", "tollgate.db"),
            signing_key=get("TOLLGATE_SIGNING_KEY", DEFAULT_SIGNING_KEY),
            admin_token=get("TOLLGATE_ADMIN_TOKEN", DEMO_ADMIN_TOKEN),
            agent_token=get("TOLLGATE_AGENT_TOKEN", DEMO_AGENT_TOKEN),
            paypal_client_id=get("PAYPAL_CLIENT_ID"),
            paypal_client_secret=get("PAYPAL_CLIENT_SECRET"),
            paypal_base_url=base_url,
            paypal_webhook_id=get("PAYPAL_WEBHOOK_ID"),
            paypal_merchant_id=get("PAYPAL_MERCHANT_ID"),
            public_base_url=public_url,
            anthropic_api_key=get("ANTHROPIC_API_KEY"),
            judge_model=get("TOLLGATE_JUDGE_MODEL", "claude-haiku-5-5"),
            agent_model=get("TOLLGATE_AGENT_MODEL", "claude-sonnet-5-5"),
            quote_ttl_seconds=int(get("TOLLGATE_QUOTE_TTL", "900")),
        )
