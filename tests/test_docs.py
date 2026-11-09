"""Docs must not drift from what the code actually does."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tollgate.redteam import run_scorecard

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def scorecard() -> dict:
    return run_scorecard().to_dict()


def _read(name: str) -> str:
    path = ROOT / name
    if not path.exists():  # e.g. tests run from an sdist without docs
        pytest.skip(f"{name} is not shipped in this checkout")
    return path.read_text(encoding="utf-8")


def test_threat_model_lists_every_attack(scorecard: dict) -> None:
    text = _read("docs/THREAT_MODEL.md")
    missing = [s["id"] for s in scorecard["scenarios"] if s["kind"] == "attack" and f"`{s['id']}`" not in text]
    assert not missing, f"attacks missing from docs/THREAT_MODEL.md: {missing}"


@pytest.mark.parametrize("name", ["README.md", "docs/THREAT_MODEL.md"])
def test_docs_quote_the_real_dollar_figures(scorecard: dict, name: str) -> None:
    text = _read(name)
    figures = [scorecard["baseline"]["usd_lost"]] + [level["usd_lost"] for level in scorecard["levels"]]
    for amount in figures:
        assert f"${amount}" in text, f"{name} does not mention ${amount}"


def test_readme_headline_counts_match(scorecard: dict) -> None:
    text = _read("README.md")
    counts = scorecard["counts"]
    assert f"{counts['scenarios']} scenarios ({counts['attacks']} attacks, {counts['benign']} legitimate orders)" in text
    # the succeeded column, level by level: 20, 9, 2, 0
    succeeded = [scorecard["baseline"]["succeeded"]] + [lv["attacks"]["succeeded"] for lv in scorecard["levels"]]
    assert succeeded == [20, 9, 2, 0]


def test_readme_links_point_at_real_files() -> None:
    text = _read("README.md")
    for target in re.findall(r"\]\((?!https?://|#)([^)\s]+)\)", text):
        assert (ROOT / target).exists(), f"README links to a missing file: {target}"


def test_env_example_names_every_setting() -> None:
    text = _read(".env.example")
    for key in (
        "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "ANTHROPIC_API_KEY",
        "TOLLGATE_SIGNING_KEY",
        "TOLLGATE_ADMIN_TOKEN",
        "TOLLGATE_AGENT_TOKEN",
        "PUBLIC_BASE_URL",
    ):
        assert key in text, f".env.example does not mention {key}"
    # the example file must never ship a real-looking secret
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            _, _, value = line.partition("=")
            assert value.strip() in ("", "http://localhost:8000"), f"unexpected value in .env.example: {line}"
