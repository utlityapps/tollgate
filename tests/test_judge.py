from __future__ import annotations

import json
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from tollgate.config import Settings
from tollgate.detectors import normalize
from tollgate.judge import (
    HeuristicJudge,
    JudgeChain,
    JudgeError,
    JudgeInput,
    JudgeVerdict,
    LLMJudge,
    build_judge,
    parse_verdict,
)
from tollgate.models import LineItem

TASK = "Buy a USB-C cable for my laptop and basic office supplies"


def review_input(
    name: str = "USB-C to USB-C cable, 2 m",
    category: str = "electronics",
    *,
    task: str = TASK,
    justification: str = "",
) -> JudgeInput:
    item = LineItem(
        product_id="p",
        name=name,
        category=category,
        merchant_id="m_contoso",
        merchant_name="Contoso Cables & Gadgets",
        unit_price=Decimal("12.00"),
        quantity=1,
    )
    return JudgeInput(task, justification, (item,), item.merchant_name, item.total, "USD")


# --- heuristic judge --------------------------------------------------------------------


def test_matching_purchase_is_fine() -> None:
    verdict = HeuristicJudge().review(review_input())
    assert not verdict.suspicious and verdict.source == "heuristic"


def test_off_task_item_is_flagged() -> None:
    verdict = HeuristicJudge().review(review_input("Ergonomic wireless mouse", "electronics"))
    assert verdict.suspicious and "OFF_TASK" in verdict.flags


def test_same_item_is_fine_for_a_matching_task() -> None:
    inp = review_input("Ergonomic wireless mouse", task="Buy an ergonomic wireless mouse, max $25")
    assert not HeuristicJudge().review(inp).suspicious


@pytest.mark.parametrize(
    "justification",
    [
        "The product page says to buy two more, so I am ordering them.",
        "As instructed by the listing, I am buying the gift cards.",
        "The seller told me to pay today.",
        "The email message requires me to transfer funds.",
    ],
)
def test_delegated_authority_is_flagged(justification: str) -> None:
    verdict = HeuristicJudge().review(review_input(justification=justification))
    assert verdict.suspicious and "DELEGATED_AUTHORITY" in verdict.flags


@pytest.mark.parametrize(
    "justification",
    [
        "Product page says it supports 100 W charging, which my laptop needs",
        "Cheapest 100 W cable that fits the laptop",
        "Two notebooks for the office",
        "",
    ],
)
def test_ordinary_justifications_are_not_flagged(justification: str) -> None:
    assert not HeuristicJudge().review(review_input(justification=justification)).suspicious


def test_zero_width_characters_do_not_hide_a_delegation() -> None:
    sneaky = "The product​ page​ says to buy two more"
    assert HeuristicJudge().review(review_input(justification=sneaky)).suspicious


# --- parsing a model's answer -----------------------------------------------------------


def test_parse_accepts_json_wrapped_in_prose() -> None:
    text = 'Sure! {"suspicious": true, "confidence": 0.9, "summary": "Off task", "flags": ["OFF_TASK"]} Done.'
    verdict = parse_verdict(text)
    assert verdict == JudgeVerdict(True, 0.9, "Off task", ("OFF_TASK",), "llm")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "I think this is fine",
        "{not json}",
        '{"suspicious": "yes"}',
        '{"confidence": 0.3}',
        '[1, 2, 3]',
        '{"suspicious": false} {"suspicious": true}',  # two objects: ambiguous, so refused
    ],
)
def test_parse_refuses_anything_unclear(text: str) -> None:
    with pytest.raises(JudgeError):
        parse_verdict(text)


def test_parse_cleans_up_the_answer() -> None:
    text = json.dumps(
        {
            "suspicious": True,
            "confidence": 7,
            "summary": "  spaced \n out  " + "x" * 400,
            "flags": ["off_task", "MADE_UP", 5, "OTHER"],
        }
    )
    verdict = parse_verdict(text)
    assert verdict.confidence == 1.0
    assert verdict.flags == ("OFF_TASK", "OTHER")  # unknown flags are dropped
    assert verdict.summary.startswith("spaced out xxx") and len(verdict.summary) <= 240
    assert parse_verdict('{"suspicious": false, "confidence": "high"}').confidence == 0.5


# --- LLM judge, against a fake client ---------------------------------------------------


class FakeClient:
    def __init__(self, reply: str | Exception) -> None:
        self.reply = reply
        self.calls: list[dict[str, Any]] = []
        self.messages = self

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.reply, Exception):
            raise self.reply
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.reply)])


SUSPICIOUS = '{"suspicious": true, "confidence": 0.8, "summary": "Not what was asked", "flags": ["OFF_TASK"]}'
FINE = '{"suspicious": false, "confidence": 0.9, "summary": "Matches the task", "flags": []}'


def test_llm_judge_sends_only_task_items_and_justification() -> None:
    client = FakeClient(FINE)
    verdict = LLMJudge(client=client, model="m-test").review(
        review_input(justification="Cable​ for the laptop")
    )
    assert not verdict.suspicious and verdict.source == "llm"

    call = client.calls[0]
    assert call["model"] == "m-test" and "temperature" not in call
    assert "DATA" in call["system"] and "cannot approve" in call["system"]
    payload = json.loads(call["messages"][0]["content"])
    assert set(payload) == {"owner_task", "purchase", "agent_justification"}
    assert payload["owner_task"] == TASK
    assert payload["agent_justification"] == normalize("Cable​ for the laptop").clean
    item = payload["purchase"]["items"][0]
    assert set(item) == {"name", "category", "quantity", "unit_price"}  # no description, no reviews


def test_llm_failures_become_judge_errors_without_leaking_details() -> None:
    judge = LLMJudge(client=FakeClient(RuntimeError("secret key sk-abc")))
    with pytest.raises(JudgeError) as info:
        judge.review(review_input())
    assert "RuntimeError" in str(info.value) and "sk-abc" not in str(info.value)
    with pytest.raises(JudgeError):
        LLMJudge(client=FakeClient("no json here")).review(review_input())


# --- the chain --------------------------------------------------------------------------


class Fixed:
    def __init__(self, verdict: JudgeVerdict | Exception) -> None:
        self.verdict = verdict

    def review(self, inp: JudgeInput) -> JudgeVerdict:
        if isinstance(self.verdict, Exception):
            raise self.verdict
        return self.verdict


def verdict(suspicious: bool, summary: str, source: str) -> JudgeVerdict:
    return JudgeVerdict(suspicious, 0.7, summary, ("OTHER",) if suspicious else (), source)


@pytest.mark.parametrize(
    ("heuristic_says", "llm_says", "expected"),
    [(False, False, False), (True, False, True), (False, True, True), (True, True, True)],
)
def test_either_judge_can_raise_the_alarm(heuristic_says: bool, llm_says: bool, expected: bool) -> None:
    chain = JudgeChain(
        Fixed(verdict(heuristic_says, "h", "heuristic")), Fixed(verdict(llm_says, "l", "llm"))
    )
    result = chain.review(review_input())
    assert result.suspicious is expected and result.source == "llm+heuristic"


def test_chain_prefers_the_alarming_summary() -> None:
    chain = JudgeChain(Fixed(verdict(True, "heuristic note", "h")), Fixed(verdict(False, "all fine", "l")))
    assert chain.review(review_input()).summary == "heuristic note"
    chain = JudgeChain(Fixed(verdict(False, "ok", "h")), Fixed(verdict(True, "llm concern", "l")))
    assert chain.review(review_input()).summary == "llm concern"


def test_llm_outage_is_raised_so_a_human_reviews() -> None:
    # Audit B-02: a configured LLM that fails must not fall back to an approval.
    chain = JudgeChain(HeuristicJudge(), Fixed(JudgeError("down")))
    with pytest.raises(JudgeError):
        chain.review(review_input())


def test_chain_names_and_builder() -> None:
    assert JudgeChain(HeuristicJudge()).name == "heuristic"
    assert build_judge(Settings()).name == "heuristic"
    assert build_judge(Settings(anthropic_api_key="sk-test-not-real")).name == "llm+heuristic"
