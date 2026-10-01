# Changelog

## v1.0.0 — stable CI regression runner

- Add 22 benign controls across all nine categories. New unwanted notices or blocks fail the CI gate; control errors stay separate from false positives.
- Add `--isolate` to test each target policy in a temporary home and cwd, using native pack selection and verified artifact hashes. Missing or ambiguous targets fail before writing results.
- Define the v1 CLI, exit-code, and JSON compatibility contract. Schema 1 keeps attacks under `results` and adds `controls`, mode metadata, and control counts.
- Validate failproofai 1.0.3 and 1.0.9 with all, default, and isolated policy configurations. CI covers Node 22/24 on Ubuntu/macOS.
- Correct deletion probes to target catastrophic paths, the bearer-token policy name, and the protected-branch target for a main push with lease. Add controls for intentionally permitted project cleanup and feature-branch force-with-lease. Preview baselines require review because these payloads changed.
- Reject output aliases as baselines, including hard links.

Reviewed all-policy snapshot: **30/45 held, 8 notices, 7 allowed, 0 errors**; **21/22 benign controls allowed**. Isolation holds **29/45**; defaults hold **16/45** and allow all 22 controls. Both engines match on the pinned policy pack `FailproofAI/policies@06b802b63f4f`.

The blocked quoted deletion example is a recorded upstream false positive. Isolating `protect-env-vars` also exposes a procfs read that the all-policy configuration catches through another policy. This release stabilizes the benchmark runner; its scope remains per-call hook decisions.

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
