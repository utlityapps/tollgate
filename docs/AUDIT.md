# Independent security audit (2026-11-11)

Tollgate was built with Claude Code. To check that work, two separate Claude sessions audited the code
from a fresh context: they had never seen the conversation that built it and were told to assume the
author was optimistic. Each worked to the same written brief:

- **Role:** a senior security engineer doing an adversarial audit, read-only access to the repository.
- **Constraints:** report only security and correctness issues; mark a finding CONFIRMED only after a
  proof-of-concept against the real code reproduces it; mark disproved hypotheses REFUTED and name the
  line that stops them; return a fixed JSON schema.
- **Method (chain of verification):** read the code and its tests, list at least three breaking points
  per area, try to prove each, classify, propose the smallest fix.
- **Grounding:** one worked example of a finding in the exact format required.
- **Scope:** Auditor A took payments and trust boundaries (quotes, policy, store, API, PayPal client,
  config). Auditor B took detectors, the judge, the agent-facing views, the red team and the dashboard,
  and checked every public claim in the submission against the code.

Each CONFIRMED finding was then reproduced again outside the auditor's session, fixed, and given a
regression test in [`tests/test_audit_regressions.py`](../tests/test_audit_regressions.py). Every test
of a fix fails on the code before the fix. The red-team scorecard is unchanged by the fixes.

## Findings and fixes

| ID | Severity | Finding | Fix |
|---|---|---|---|
| A-01 | High | `tollgate serve` started on a public address with the public demo tokens, and `/api/health` named the demo admin token to anyone. | The server refuses a non-loopback address while any demo secret is in use (opt-in `TOLLGATE_ALLOW_DEMO_SECRETS=1` for a throwaway demo). The health hint is only sent to a browser on the same machine. |
| B-01 | High | The `ROLE_SPOOF` regex backtracked quadratically: one 20,000-space `context` froze the whole server for about 20 seconds. | Rewrote the pattern with possessive quantifiers. A test bounds every detector on long whitespace input. |
| A-02 | Medium | With the default signing key, an agent could sign its own quotes with any price, a relabelled merchant, or a ten-year expiry. | Covered by A-01's refusal, plus defence in depth: a quote whose price, merchant, currency, quantity or lifetime disagrees with the catalog is rejected even when its signature is valid. |
| A-03 | Medium | On mock payments, a constant header made any webhook "verified", so forged events could uncount spend or mark a payment refunded. | The mock backend rejects webhooks unless a test enables them. Webhooks may only move an order along a legal path (DENIED only before capture, REFUNDED and REVERSED only after). |
| A-04 | Medium | The daily limit was keyed on when the agent asked, so an order a human approved near the 24-hour mark stopped counting minutes after it was paid. | Spend is now counted from when the PayPal order is created (`counted_at`). |
| A-05 | Medium | An order whose capture failed stopped counting toward the daily limit but could still be captured later. | `capture_failed` counts as spend. |
| A-06 | Medium | The pre-capture check read only the first purchase unit, so an order with a second unit or a different payee could be captured. | Orders must have exactly one purchase unit; the captured total is summed across every capture; the payee is checked against `PAYPAL_MERCHANT_ID` when it is set. |
| B-02 | Medium | If the Claude judge was configured but failed (outage, timeout, non-JSON reply), Tollgate fell back to the rule-based verdict and could approve, contrary to the claim that a model error escalates. | A failing LLM judge now raises, the engine records `JUDGE_ERROR`, and the order waits for a human. |
| B-03 | Medium | Instructions written with Cyrillic or Greek look-alike letters, or broken up by default-ignorable characters outside the zero-width list, were not detected. | All default-ignorable characters are stripped (blank filler letters read as spaces), and patterns are also matched on a copy with look-alike letters folded to Latin. |
| A-07 | Low | Revoking a mandate did not stop orders that were already open. | Capture re-checks that the mandate is active and unexpired. |
| B-04 | Low | Merchant names were never scanned for injected instructions. | Merchant names go through the same detectors as other listing text. |
| B-05 | Low | The look-alike merchant check missed Greek letters and "rn" for "m". | The skeleton folds Greek and Cyrillic look-alikes, `rn` to `m` and `vv` to `w`. |
| B-06 | Low | The claim that the Claude judge "sees no listing text" was wrong: it sees product and merchant names. | Claim corrected: the judge sees names (capped at 80 characters), never descriptions or reviews; a reply it cannot parse escalates (B-02). |
| B-07 | Info | The dashboard was also served at `/static/dashboard.html` without the content security policy. | Every `/static/` response carries the dashboard policy. |
| A-08 | Low | The daily-limit check is atomic only inside one process. Several workers sharing one SQLite file could each approve against the old total. | Not fixed. Documented: run one process (the CLI and Docker image do). |

## Hypotheses the auditors tried and could not break

- The agent API and the five MCP tools take no price, payee or amount (claim 1).
- Edited, replayed (including re-encoded tokens), cross-mandate, expired and concurrently replayed quotes
  are rejected; 32 threads replaying one quote produced one order (claim 2).
- In one process, double approve/deny, double capture and double refund each produce exactly one
  provider call; limits are re-checked at approval; the agent token cannot reach owner routes (claims 6, 8, 13).
- The sandbox-only host guard held against URL parser tricks (claim 11).
- No attacker-controlled text reaches the agent through reasons or errors (claim 9).
- No judge path can loosen a rule's decision (claim 19).
- `tollgate redteam` reproduces the published numbers exactly, offline (claim 16).
- The CSV export guard held in LibreOffice for every bypass tried (Excel untested).

## What remains

- Pattern detectors can still be bypassed by paraphrase or another language. The hard bound (signed quotes
  and mandate limits) is what caps the loss.
- Mock payments have no buyer sign-in by design, so anyone with a mock payment link can approve it. Mock
  mode moves no money.
- The red-team scenarios were written by the same project; this audit is a second look, not a proof.
