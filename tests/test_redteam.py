from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest

from tollgate.cli import main
from tollgate.redteam import SCENARIOS, run_scorecard


@pytest.fixture(scope="module")
def card() -> dict[str, Any]:
    return run_scorecard().to_dict()


def test_every_scenario_behaves_as_expected() -> None:
    scorecard = run_scorecard()
    assert scorecard.passed
    assert "RESULT: all scenarios behaved as expected" in scorecard.render_text()


def test_scenario_catalogue(card: dict[str, Any]) -> None:
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids)) == 26
    assert card["counts"] == {"scenarios": 26, "attacks": 20, "benign": 6}
    assert all(s.kind in ("attack", "benign") for s in SCENARIOS)
    assert all(s.expect <= {"DENY", "ESCALATE"} for s in SCENARIOS if s.kind == "attack")
    assert all(s.expect <= {"APPROVE", "ESCALATE"} for s in SCENARIOS if s.kind == "benign")


def test_each_layer_stops_attacks_the_one_below_missed(card: dict[str, Any]) -> None:
    succeeded = [card["baseline"]["succeeded"]] + [lvl["attacks"]["succeeded"] for lvl in card["levels"]]
    assert succeeded == [20, 9, 2, 0]
    assert [lvl["id"] for lvl in card["levels"]] == ["limits", "detectors", "full"]


def test_no_benign_order_is_blocked_at_any_level(card: dict[str, Any]) -> None:
    for level in card["levels"]:
        assert level["benign"]["false_positives"] == 0, level["id"]
    assert card["levels"][-1]["benign"]["ok"] == card["counts"]["benign"]


def test_dollars_protected(card: dict[str, Any]) -> None:
    assert Decimal(card["baseline"]["usd_lost"]) > 0
    assert card["levels"][-1]["usd_lost"] == "0.00"
    assert card["headline"].startswith("20 of 20 attacks stopped, 6 of 6 benign orders")


def test_layers_catch_what_they_are_credited_with(card: dict[str, Any]) -> None:
    for s in card["scenarios"]:
        if s["kind"] != "attack":
            continue
        results = s["results"]
        if s["stopped_by"] == "detectors":
            assert results["limits"]["outcome"] != "DENY", s["id"]  # only the detectors deny it
            assert results["detectors"]["outcome"] in s["expect"], s["id"]
        if s["stopped_by"] == "judge":
            assert results["detectors"]["outcome"] == "APPROVE", s["id"]  # only the judge notices
            assert results["full"]["outcome"] in s["expect"], s["id"]
        if s["stopped_by"] in ("policy", "quotes", "payments"):
            assert results["limits"]["outcome"] == "DENY", s["id"]  # no detector or judge needed


def test_scorecard_is_reproducible(card: dict[str, Any]) -> None:
    again = run_scorecard().to_dict()
    for key in ("counts", "baseline", "levels", "scenarios", "passed", "headline"):
        assert again[key] == card[key], key


def test_scorecard_is_json(card: dict[str, Any]) -> None:
    assert json.loads(json.dumps(card))["passed"] is True


def test_cli_prints_the_scorecard(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["redteam"])
    out = capsys.readouterr().out
    assert stop.value.code == 0 and "Tollgate red-team scorecard" in out
    assert "No firewall (baseline)" in out and "quote-replay" in out


def test_cli_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["redteam", "--json"])
    assert stop.value.code == 0 and json.loads(capsys.readouterr().out)["passed"] is True
