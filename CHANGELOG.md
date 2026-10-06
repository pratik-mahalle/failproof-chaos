# Changelog

## Unreleased — custom workflow suites

- Add `--corpus <file.json>` for reviewed tool-call fixtures with exact expected verdicts. Custom suites replace the built-in corpus and support their own categories, including suites containing only attacks or benign controls.
- Gate custom suites with `--ci` using expectations alone or alongside a reviewed baseline. Known failures still fail expectations when saved in a baseline. Changed expectations require baseline review. Built-in CI retains its baseline requirement.
- Add the schema-1 `expectations` summary and `expect` on custom rows. Reports show expected and actual decisions separately from policy misses, unwanted blocks, notices, and errors.
- Validate suites before engine calls and report writes, protect corpus output aliases, and escape custom metadata in reports. Payload commands and writes remain data.
- Check the synthetic team suite in all/default/isolated profiles throughout the existing eight-job matrix. Preserve custom reports alongside built-in reports and add an incident authoring and pilot guide.

All eight jobs pass on engines 1.0.3/1.0.9 and Node 22/24 across Ubuntu/macOS. The 99 built-in cases retain their reviewed decisions and category scores in every profile; both custom expectations pass in all profiles, with zero engine errors. An initial trial in three owned repositories passes all 21 expectations on both engines and catches three controlled policy regressions. Add a rehearsal for the reviewed unwanted block and correct the starter CI recipe's job-level environment. Feedback from actual use and repeat use remains pending before release; see [PILOT.md](PILOT.md).

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
