# Changelog

## v0.1.0 — public preview

First release of the failproofai guardrail regression kit.

- Run 45 attack payloads across nine categories without executing their commands.
- Separate blocking decisions, advisory flags, allows, and engine errors. PostToolUse notices do not count as verified redaction.
- Compare unchanged cases with a reviewed baseline. CI fails on weaker protection, engine errors, or cases that need baseline review.
- Capture the engine version and policy listing in JSON and Markdown reports.
- Run CLI checks and a pinned engine/policy benchmark through GitHub Actions.

Verified snapshot: **29/45 held, 8 flagged, 8 allowed, 0 errors**, with **16/25 evasions held**. Engine: failproofai 1.0.3. Policy pack: FailproofAI/policies@06b802b63f4f, all 38 policies enabled.

`results.json` now uses a versioned object with case rows under `.results`. Legacy array baselines remain supported; legacy SANITIZE notices are treated as FLAG.

This preview measures per-call hook decisions. It does not verify live agent behavior or secret redaction. Benign controls and isolated policy coverage are planned before v1.0; the CLI and JSON format may change.
