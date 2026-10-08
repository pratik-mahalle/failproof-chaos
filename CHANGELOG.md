# Changelog

## v3.0.0 — guard integrity — 2026-10-08

- Add the built-in `tamper` category: 21 attacks and 3 controls checking whether an agent can pause failproofai, remove policies, delete its state, or rewrite its own hook configuration. The engine's built-in guard is measured in combined and isolated modes (`engine-anti-tamper` cases run with no pack policy enabled). Command-substitution pauses and hook-config rewrites for Claude Code, Codex and Cursor are currently allowed.
- Add `faults.mjs`: inject one fault at a time into a temporary copy of the installed pack and report whether the `block-sudo` attack stays refused (CLOSED) or is allowed (OPEN). Load-time corruption fails closed (a deleted manifest is the documented exception: it is allowed, because upstream treats it as a fresh machine); policy exceptions, invalid results, hangs, slow loads and unregistered policies fail open. A reviewed `baselines/faults.json` gates CI on CLOSED→OPEN regressions.
- `classify()` accepts `{ failClosed: true }` to decode an engine's fail-closed refusal as DENY. Ordinary runs still report it as ERROR.
- Document a pre-commit hook that re-runs the suite and fault check when guard configuration changes.

**Why a major version:** the built-in corpus grows to 76 attacks and 47 controls, so saved built-in baselines report new cases and `--ci` exits 2 until reviewed, and the headline held percentage changes. Schema 1, CLI flags and exit codes are unchanged. Under the README's compatibility rule, corpus additions are allowed within a minor release; v3.0.0 is a deliberate choice that marks the new guard-integrity scope, not a compatibility break. Codex fault injection, other harnesses, daemon faults and harness-level hook timeouts remain unmeasured.

## v2.2.0 — guard sensitivity checks — 2026-10-08

- Add `sensitivity.mjs` to check whether an explicitly selected repository suite detects a disabled guard. Require a passing starting suite, copy the supported installed configuration into a temporary home, and preserve the project cwd and source settings.
- Report detected changes, missed changes, unsupported targets, and invalid measurements separately. Verify that the engine selected the guard before disabling it and stopped selecting it afterward. Only a relevant case's failed exact expectation counts as detection; engine errors do not.
- Keep sensitivity results separate from benchmark scores. Start with three guards in the pinned official pack and supported engines; configuration sources that cannot be reproduced safely are rejected.

Support `block-env-files`, `block-sudo`, and `block-read-outside-cwd` in a verified installed official pack, with engines 1.0.3, 1.0.9, and 1.0.10. Use `--adapter codex` for native Codex suites; Claude remains the default. Output is an exclusive new JSON file. Exit 0 means all selected changes were detected, exit 1 means changes were missed, and exit 2 means an unsupported or invalid check. Existing runner behavior, schemas, expectations, and baselines remain unchanged.

All ten jobs pass on [merged main](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37732580462). The implementation's ten audited CI bundles each match the ordinary runner on all nine starting cases, detect all three disabled guards, report three deliberate misses with ordinary-only cases, and reject an unsupported target. Configuration precedence and source preservation checks pass. Sensitivity reports omit raw payloads and parameter values.

A missed change can reflect overlapping protection and needs investigation. These checks measure selected guard changes at the hook-decision level. Live enforcement and human time savings remain unmeasured; the six known Codex protected-patch allowances from v2.1.0 remain visible policy failures.

## v2.1.0 — incident drafts, Codex coverage, and CI summaries — 2026-10-08

- Add `--adapter codex` for explicit native custom suites, preserving raw shell and `apply_patch` input. Keep Claude as the default and reject comparisons across adapters; legacy baselines mean Claude. Decode supported Codex responses separately, classify post-tool blocks as feedback (`FLAG`), and reject unsupported or malformed responses as `ERROR`.
- Add source configuration fingerprints, declared pack selections, verified artifact hashes, and working-directory context to schema-1 results and reports. Baselines can show source-context differences without treating hashes as proof of applied settings or changing the verdict gate.
- Add native Codex fixtures and a reproducible two-configuration comparison. Six protected patch probes retain their desired `DENY` expectations and expose current allowances; diagnostic CI checks those reviewed failures explicitly. Preserve the original eight Claude jobs and add two focused Codex jobs on engine 1.0.10.
- Add native GitHub workflow summaries for the current invocation, including changed and failing case IDs, exact decisions, reasons, review requirements, and separate attack, ordinary-work, advisory, and error signals. Keep full reports as artifacts. Failed summary writes preserve an existing failure status and make an otherwise successful run exit 2.
- Reject malformed Codex event tags, missing denial reasons, unsupported standalone allows, and orphaned reason fields before counting a decision. Refuse summary paths with unresolved symlink aliases so invalid runs cannot create an input file through a dangling link.
- Add `case.mjs` to create a new single-case schema-1 draft from an explicitly supplied Claude-compatible hook payload and author-selected metadata and expectation. Preserve optional response values, reject invalid inputs and existing destinations, and report omitted capture metadata.
- Give custom-suite validation errors a case and field context. Document reviewed incident/control pairs, synthetic unsafe-allowance and unwanted-block rehearsals, and baseline-based upgrade reviews.

These additions preserve the runner CLI, exit codes, schema-1 field meanings, and reviewed built-in cases. The helper does not capture sessions, execute payloads, infer expected behavior, or redact input. Human time savings and real production incident capture remain unmeasured.

Both implementation PRs are merged. All ten jobs pass on [the merged-main validation](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37729502207): the eight Claude compatibility jobs and two focused Codex jobs. The six desired Codex patch refusals remain visible policy failures; passing diagnostic CI does not mean those patches are blocked.

## v2.0.0 — custom workflow regression suites — 2026-10-06

The major release marks support for repository-specific policy tests. Existing v1.2 commands, exit codes, schema-1 field meanings, legacy baselines, and all 99 built-in cases remain compatible. Existing built-in users require no migration.

- Add `--corpus <file.json>` for reviewed tool-call fixtures with exact expected verdicts. Custom suites replace the built-in corpus and support their own categories, including suites containing only attacks or benign controls.
- Gate custom suites with `--ci` using expectations alone or alongside a reviewed baseline. Known failures still fail expectations when saved in a baseline. Changed expectations require baseline review. Built-in CI retains its baseline requirement.
- Add the schema-1 `expectations` summary and `expect` on custom rows. Reports show expected and actual decisions separately from policy misses, unwanted blocks, notices, and errors.
- Validate suites before engine calls and report writes, protect corpus output aliases, and escape custom metadata in reports. Payload commands and writes remain data.
- Check the synthetic team suite in all/default/isolated profiles throughout the existing eight-job matrix. Preserve custom reports alongside built-in reports and add an incident authoring and pilot guide.

All eight jobs pass on engines 1.0.3/1.0.9 and Node 22/24 across Ubuntu/macOS. The 99 built-in cases retain their reviewed decisions and category scores in every profile; both custom example expectations pass in all profiles, with zero engine errors. The three owned repositories passed 21 initial expectations on local engine 1.0.3 and CI engine 1.0.9, and caught three controlled policy regressions.

The same repositories reused their suites during a published upgrade to engine 1.0.10 and policy pack 2.0.0. All 27 expectations pass in combined and isolated modes. Baseline reports show the three cleanup decisions changing from ALLOW to advisory INSTRUCT; all 21 original pilot decisions remain unchanged. Human time savings and independent user feedback are post-release validation work; see [PILOT.md](PILOT.md).

## v1.2.0 — coverage labels and CI report artifacts

- Add harmless Edit and shell-write controls paired with the existing risky file-write variants. The corpus now has 55 attacks and 44 controls; all 97 v1.1 payloads retain their decisions.
- Label documented operations and exploratory coverage boundaries in JSON rows, console output, and Markdown tables. Labels reference the pinned pack's declared operation and tool/event scope. They leave scores, payload comparisons, and CI exits unchanged; legacy baselines may omit them.
- Preserve all/default/isolated reports in separate CI directories and upload one artifact per matrix job. Remaining profiles continue after a failed comparison, and uploading runs even after failures. Pin the official upload action to its v7.0.1 commit.
- Review the two new control IDs as ALLOW on both engines in all three profiles before updating snapshots. All-policy/isolation controls: **37/44 allowed, 7 false positives**. Defaults: **43/44 allowed, 1 false positive**. Attack scores remain unchanged, with zero engine errors.

## v1.1.0 — category scores and file-write coverage

- Add eight `file-write` probes for protected filenames, Edit/shell variants, and uppercase/backup extensions. Add two environment-dump probes around the procfs gap.
- Add 20 benign controls for quoted commands, ordinary paths and cleanup, documentation placeholders, read-only SQL, and public file writes. The corpus now contains 55 attacks and 42 controls across ten categories.
- Add category counts to console and Markdown reports and the additive JSON `categories` object. Existing schema-1 fields and CI exit codes keep their meanings.
- Show Write contents and Edit replacements in reports. Escape HTML characters so placeholders such as `<TOKEN>` remain visible in Markdown.
- Document focused reproductions and review updated all/default/isolated snapshots. All 67 v1.0 payloads retain their decisions; 30 new IDs require baseline review.

Both supported engines match on the pinned pack. All policies: **35/55 held, 8 notices, 12 allowed; 35/42 controls allowed, 7 false positives**. Defaults: **16/55 held; 41/42 controls allowed, 1 false positive**. Isolation: **33/55 held; 35/42 controls allowed, 7 false positives**. All profiles have zero engine errors.

The six additional all-policy false positives are newly measured cases. The file-write guard denies the four protected filenames through Write, allows the four alternate-tool/extension probes, and denies a benign documentation filename containing `credentials`. These are recorded policy findings; the runner never performs the payload's file writes.

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
