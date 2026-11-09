"""Deterministic detectors for prompt injection, hidden text, risky purchases and fraud.

They run on every purchase request and are intentionally boring: regexes, Unicode
normalisation and arithmetic. The LLM judge can add caution on top, but it can never
override a rule that says DENY.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from .models import Finding, Severity

_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "᠎", "­"}
_BIDI = {
    "‎", "‏", "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}  # fmt: skip
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_STYLE_ATTR = re.compile(r"style\s*=", re.IGNORECASE)
_CSS_HIDE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:#fff(?:fff)?|white)\b",
    re.IGNORECASE,
)
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:==|=)?")


@dataclass
class Normalized:
    clean: str
    zero_width: int = 0
    bidi: int = 0
    smuggled: str = ""
    html_comments: list[str] = field(default_factory=list)
    css_hidden: bool = False


def normalize(text: str | None) -> Normalized:
    """Strip invisible characters, decode Unicode-tag smuggling, apply NFKC."""
    text = text or ""
    kept: list[str] = []
    smuggled: list[str] = []
    zero_width = bidi = 0
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:  # Unicode "tag" block: invisible ASCII
            ascii_cp = cp - 0xE0000
            if 0x20 <= ascii_cp < 0x7F:
                smuggled.append(chr(ascii_cp))
            continue
        if ch in _ZERO_WIDTH:
            zero_width += 1
            continue
        if ch in _BIDI:
            bidi += 1
            continue
        kept.append(ch)
    clean = unicodedata.normalize("NFKC", "".join(kept))
    return Normalized(
        clean=clean,
        zero_width=zero_width,
        bidi=bidi,
        smuggled="".join(smuggled),
        html_comments=[c.strip() for c in _HTML_COMMENT.findall(clean)],
        css_hidden=bool(_STYLE_ATTR.search(clean) and _CSS_HIDE.search(clean)),
    )


class Pattern(NamedTuple):
    name: str
    regex: re.Pattern[str]
    severity: Severity
    detail: str


def _p(name: str, rx: str, severity: Severity, detail: str) -> Pattern:
    return Pattern(name, re.compile(rx, re.IGNORECASE | re.MULTILINE), severity, detail)


PATTERNS: list[Pattern] = [
    _p(
        "OVERRIDE_PRIOR",
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,40}?"
        r"\b(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|policies|policy|limits?)\b",
        Severity.CRITICAL,
        "Tries to override the agent's prior instructions",
    ),
    _p(
        "CONCEAL_FROM_USER",
        r"\b(?:do not|don't|never|without)\b[^.\n]{0,25}?"
        r"\b(?:tell|inform|notify|alert|mention|show|ask|warn)\b[^.\n]{0,25}?"
        r"\b(?:the |your )?(?:user|owner|human|customer|buyer|principal)\b",
        Severity.CRITICAL,
        "Tells the agent to hide something from its owner",
    ),
    _p(
        "REDIRECT_PAYMENT",
        r"\b(?:change|update|switch|replace|redirect|set)\b[^.\n]{0,25}?"
        r"\b(?:payee|merchant|recipient|beneficiary|payment (?:address|account|destination)|"
        r"shipping address|delivery address|paypal (?:email|account))\b",
        Severity.CRITICAL,
        "Tries to redirect the payment",
    ),
    _p(
        "PREAPPROVAL_CLAIM",
        r"\b(?:user|owner|customer|buyer|principal|you)\b[^.\n]{0,30}?"
        r"\b(?:has|have|had|already|pre-?)\s*(?:pre-?)?(?:approved|authori[sz]ed|consented|confirmed|agreed)\b",
        Severity.HIGH,
        "Claims the owner already approved purchases",
    ),
    _p(
        "PREAPPROVED_PURCHASES",
        r"\bpre-?approved\b[^.\n]{0,40}\b(?:purchases?|payments?|orders?|transactions?)\b",
        Severity.HIGH,
        "Claims purchases are pre-approved",
    ),
    _p(
        "SKIP_CONFIRMATION",
        r"\b(?:without|skip|bypass|no need for|do not (?:ask|wait) for|don't (?:ask|wait) for)\b[^.\n]{0,30}?"
        r"\b(?:confirmation|approval|permission|consent|verification|human review|asking)\b",
        Severity.HIGH,
        "Tells the agent to skip confirmation or approval",
    ),
    _p(
        "ADDRESS_AGENT",
        r"\b(?:note|message|instructions?|attention|important|reminder|hey)\s*(?:to|for)\s*"
        r"(?:any\s+|all\s+|the\s+)?(?:ai|llm|assistants?|agents?|bots?|models?)\b",
        Severity.HIGH,
        "Speaks directly to AI agents",
    ),
    _p(
        "AGENT_MUST",
        r"\b(?:ai|llm|assistant|agent|bot|model)s?\b[^.\n]{0,40}?"
        r"\b(?:must|should|need to|have to|are required to|shall)\b[^.\n]{0,60}?"
        r"\b(?:buy|purchase|order|pay|send|transfer|checkout|add to cart|approve)\b",
        Severity.HIGH,
        "Orders the agent to spend money",
    ),
    _p(
        "NEW_INSTRUCTIONS",
        r"\b(?:new|updated|revised|real|actual|true|additional)\s+(?:system\s+)?"
        r"(?:instructions?|task|objective|goal|rules?)\s*[:\-]",
        Severity.HIGH,
        "Announces replacement instructions",
    ),
    _p(
        "CHANGE_PERSONA",
        r"\byou are (?:now|actually|really)\b",
        Severity.HIGH,
        "Tries to redefine what the agent is",
    ),
    _p(
        "PRIVILEGE_CLAIM",
        r"\b(?:admin|administrator|developer|system|root) (?:override|mode|access|privileges?|command)\b|"
        r"\b(?:maintenance|debug) mode\b",
        Severity.HIGH,
        "Claims special privileges or a special mode",
    ),
    _p(
        "TOOL_SYNTAX",
        r"<\s*/?\s*(?:tool_call|function_call|invoke|tool_use)\b|"
        r"\"(?:name|tool)\"\s*:\s*\"(?:request_purchase|get_quote|search_products)\"",
        Severity.HIGH,
        "Contains tool-call syntax aimed at the agent",
    ),
    _p(
        "ROLE_SPOOF",
        r"(?:^|\n)[ \t]*[\[<(]?[ \t]*(?:system|assistant|developer|admin(?:istrator)?|operator|root)"
        r"[ \t]*[\]>)]?[ \t]*[:：>]",
        Severity.MEDIUM,
        "Imitates a system, assistant or admin message",
    ),
    _p(
        "URGENT_IMPERATIVE",
        r"\b(?:buy|purchase|order|pay|send|transfer|wire|checkout)\b[^.\n]{0,60}?"
        r"\b(?:immediately|right now|asap|at once)\b",
        Severity.MEDIUM,
        "Pushes the agent to spend immediately",
    ),
    _p(
        "SEND_FUNDS",
        r"\b(?:send|transfer|wire|remit)\b[^.\n]{0,40}?\b(?:to|into)\b[^.\n]{0,40}?"
        r"\b(?:account|wallet|address|iban|paypal)\b",
        Severity.MEDIUM,
        "Asks for funds to be sent somewhere",
    ),
]

_RISKY = re.compile(
    r"\b(?:gift[ -]?cards?|e-?gift|prepaid|crypto(?:currency)?|bitcoin|btc|ethereum|usdt|"
    r"stablecoin|wire transfer|western union|money ?orders?|steam (?:wallet|cards?)|itunes|"
    r"google play (?:cards?|codes?)|store credit|vouchers?)\b",
    re.IGNORECASE,
)
_URGENCY = re.compile(
    r"\b(?:act now|limited time|expires? (?:in|soon|today)|last chance|urgent(?:ly)?|hurry|"
    r"account (?:will be )?(?:suspended|locked|closed)|final notice)\b",
    re.IGNORECASE,
)


def _match(text: str) -> list[tuple[Pattern, str]]:
    hits: list[tuple[Pattern, str]] = []
    for pattern in PATTERNS:
        m = pattern.regex.search(text)
        if m:
            hits.append((pattern, " ".join(m.group(0).split())[:100]))
    return hits


def _decoded_blobs(text: str) -> Iterator[str]:
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.strip() and (decoded.isprintable() or "\n" in decoded):
            yield decoded


def scan_text(text: str | None, field_name: str) -> list[Finding]:
    """Look for instructions aimed at an AI agent inside text the agent does not control."""
    n = normalize(text)
    raw_hits = {p.name for p, _ in _match(text or "")}
    hits: list[tuple[Pattern, str]] = _match(n.clean)
    out: list[Finding] = []

    if n.smuggled:
        out.append(
            Finding(
                code="HIDDEN_UNICODE_TEXT",
                severity=Severity.HIGH,
                detail=f"[{field_name}] Invisible Unicode tag characters smuggle a hidden message",
                source="detector",
                evidence=n.smuggled[:120],
            )
        )
        hits += [(p, f"hidden: {snippet}") for p, snippet in _match(n.smuggled)]
    if n.zero_width:
        out.append(
            Finding(
                code="INVISIBLE_CHARACTERS",
                severity=Severity.LOW,
                detail=f"[{field_name}] Contains {n.zero_width} zero-width character(s)",
                source="detector",
            )
        )
    if n.bidi:
        out.append(
            Finding(
                code="BIDI_CONTROL",
                severity=Severity.MEDIUM,
                detail=f"[{field_name}] Contains text-direction control characters",
                source="detector",
            )
        )
    if (n.zero_width or n.bidi) and any(p.name not in raw_hits for p, _ in hits):
        out.append(
            Finding(
                code="OBFUSCATED_TEXT",
                severity=Severity.HIGH,
                detail=f"[{field_name}] Instruction is only readable after invisible characters are removed",
                source="detector",
            )
        )
    if any(len(comment.split()) >= 3 for comment in n.html_comments):
        out.append(
            Finding(
                code="HIDDEN_HTML_COMMENT",
                severity=Severity.MEDIUM,
                detail=f"[{field_name}] Contains a hidden HTML comment",
                source="detector",
                evidence=" | ".join(n.html_comments)[:120],
            )
        )
    if n.css_hidden:
        out.append(
            Finding(
                code="HIDDEN_STYLED_TEXT",
                severity=Severity.MEDIUM,
                detail=f"[{field_name}] Uses CSS to hide text from humans",
                source="detector",
            )
        )
    for decoded in _decoded_blobs(n.clean):
        inner = _match(decoded)
        if inner:
            out.append(
                Finding(
                    code="ENCODED_INSTRUCTION",
                    severity=Severity.HIGH,
                    detail=f"[{field_name}] Base64 blob decodes to an instruction",
                    source="detector",
                    evidence=decoded[:120],
                )
            )
            hits += [(p, f"encoded: {snippet}") for p, snippet in inner]

    seen: set[str] = set()
    for pattern, snippet in hits:
        if pattern.name in seen:
            continue
        seen.add(pattern.name)
        out.append(
            Finding(
                code=f"INJECTION_{pattern.name}",
                severity=pattern.severity,
                detail=f"[{field_name}] {pattern.detail}",
                source="detector",
                evidence=snippet,
                blocking=pattern.severity is Severity.CRITICAL,
            )
        )
    return out


def scan_untrusted(fields: Mapping[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for name, text in fields.items():
        findings.extend(scan_text(text, name))
    return findings


def scan_risky_terms(fields: Mapping[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for name, text in fields.items():
        m = _RISKY.search(normalize(text).clean)
        if m:
            out.append(
                Finding(
                    code="RISKY_CATEGORY",
                    severity=Severity.HIGH,
                    detail=f"[{name}] Mentions gift cards, prepaid cards, crypto or wire transfers",
                    source="detector",
                    evidence=m.group(0),
                )
            )
    return out


def scan_urgency(fields: Mapping[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for name, text in fields.items():
        m = _URGENCY.search(normalize(text).clean)
        if m:
            out.append(
                Finding(
                    code="URGENCY_PRESSURE",
                    severity=Severity.LOW,
                    detail=f"[{name}] Uses urgency or threats to rush the purchase",
                    source="detector",
                    evidence=m.group(0),
                )
            )
    return out


# --- merchant look-alikes ---------------------------------------------------------

_CONFUSABLES = str.maketrans(
    {
        "I": "l", "1": "l", "|": "l", "0": "o", "5": "s", "3": "e", "4": "a", "@": "a", "$": "s",
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
        "у": "y", "і": "i", "ӏ": "l", "ѕ": "s",
        "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Х": "x",
        "У": "y", "І": "i", "Ѕ": "s",
    }
)  # fmt: skip
_PROTECTED_BRANDS = ("paypal", "amazon", "apple", "google", "microsoft", "netflix", "venmo", "fedex")


def skeleton(name: str) -> str:
    """Collapse look-alike characters so 'PayPaI' and 'PayPal' compare equal."""
    folded = unicodedata.normalize("NFKC", name).translate(_CONFUSABLES).lower()
    return re.sub(r"[^a-z]", "", folded)


def check_merchant_lookalike(merchant_name: str, trusted_names: list[str]) -> list[Finding]:
    """Flag a merchant whose name collides with a trusted one once look-alikes are folded."""
    out: list[Finding] = []
    plain = unicodedata.normalize("NFKC", merchant_name).strip()
    sk = skeleton(plain)
    for trusted in trusted_names:
        if plain.lower() != trusted.lower() and skeleton(trusted) == sk:
            out.append(
                Finding(
                    code="LOOKALIKE_MERCHANT",
                    severity=Severity.CRITICAL,
                    detail=f"Merchant '{merchant_name}' imitates verified merchant '{trusted}'",
                    source="detector",
                    evidence=merchant_name,
                    blocking=True,
                )
            )
    letters_only = re.sub(r"[^a-z]", "", plain.lower())
    for brand in _PROTECTED_BRANDS:
        if brand in sk and brand not in letters_only:
            out.append(
                Finding(
                    code="LOOKALIKE_BRAND",
                    severity=Severity.CRITICAL,
                    detail=f"Merchant '{merchant_name}' uses look-alike characters to imitate '{brand}'",
                    source="detector",
                    evidence=merchant_name,
                    blocking=True,
                )
            )
    return out


def check_velocity(
    prior_times: list[datetime],
    now: datetime,
    *,
    window_seconds: int = 600,
    threshold: int = 4,
) -> list[Finding]:
    """Many small orders in a short window is how budgets get drained one order at a time."""
    recent = [t for t in prior_times if 0 <= (now - t).total_seconds() <= window_seconds]
    if len(recent) >= threshold:
        return [
            Finding(
                code="VELOCITY",
                severity=Severity.HIGH,
                detail=(
                    f"{len(recent)} orders in the last {window_seconds // 60} minutes "
                    "(possible order structuring)"
                ),
                source="detector",
            )
        ]
    return []
