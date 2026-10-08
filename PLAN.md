# Failproof Chaos implementation plan

Turn an unsafe allowance or unwanted block into a reviewed repository test, then show whether a policy change fixes it while preserving ordinary work. Build on the custom suites, exact expectations, baseline comparisons, and reports shipped in v2.0.0.

Updated 8 October 2026. Stages 1 and 2 are merged in [PR 2](https://github.com/pratik-mahalle/failproof-chaos/pull/2), and stage 3 is merged in [PR 3](https://github.com/pratik-mahalle/failproof-chaos/pull/3). All ten jobs pass on [merged main](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37729502207). These additions form v2.1.0. Stage 4 remains planned. The completed v2.0.0 plan is retained below as release history. Human timing and independent user feedback remain post-release validation work.

## Delivery order

| Stage | Deliverable | Completion evidence |
|-------|-------------|---------------------|
| 1 | GitHub workflow summaries | A reviewer can identify changed decisions and failures without downloading reports |
| 2 | One explicit Claude hook payload becomes a draft case | A reviewed incident and ordinary counterpart run through the existing custom-suite workflow |
| 3 | Native Codex coverage and explicit configuration comparisons | Pinned adapter tests expose tool-format differences and distinguish the tested configurations |
| 4 | Optional checks that deliberately weaken a guard | The suite identifies selected disabled guards or reports missed coverage |

Stages 1 through 3 ship together in v2.1.0. Review confirmed that schema 1, existing CLI behavior, and exit codes remain compatible. Stage 4 follows as a separate change to assess whether repository suites detect selected disabled guards.

Keep the runner dependency-free. Reuse the existing evaluator, classification, comparison, and reporting behavior. Preserve the five exact expected verdicts and exit codes 0, 1, and 2. Payloads remain data; stages 1 through 4 do not execute their commands or writes. A future live-enforcement experiment needs a separate, bounded sandbox design.

## Stage 1 GitHub summaries

Make the existing CI result useful at the point where a developer reviews a change.

- [x] Add a compact Markdown summary using native `GITHUB_STEP_SUMMARY`. Reuse current result fields and comparison decisions; keep full reports as artifacts.
- [x] Label each profile with engine version, operating system, Node version, combined or isolated mode, and suite name. Display that isolation uses policy defaults.
- [x] Show expectation totals, regressions, allowed attack probes, unwanted blocks, notices, and engine errors separately. Put changed and failing case IDs, expected and actual decisions, and reasons first. Keep new, changed, and removed cases visible as review requirements.
- [x] Make advisory changes explicit. The existing cleanup example must show `ALLOW → INSTRUCT` as advice; it must not imply execution was stopped.
- [x] Generate summaries for failed jobs too. Use only outputs from the current invocation, clear or segregate old generated outputs before the run, and report missing results as an incomplete measurement. Preserve the runner's failure status if summary rendering fails.
- [x] Escape and bound untrusted text, omit full payloads from the compact summary, and link to the workflow's artifacts. Reasons may still contain input data; document this alongside the existing fixture guidance.
- [x] Update the project-root recipe so policy upgrades pass the reviewed old result to the existing `--baseline` option.

**Acceptance:** exercise a pass, unsafe allowance, unwanted block, advisory change, engine error, incomplete comparison, and failure before report generation. An old passing report must never appear as the current result. Summary counts and case decisions must agree with the JSON artifacts. A rendering error must not turn a failing policy check green.

**Likely files:** `.github/workflows/ci.yml`, `run.mjs` reporting or a small dedicated summary entry point, `test.mjs`, `PILOT.md`, and `README.md`. Share only the formatting helpers actually used by both outputs; no new reporting framework or hosted service.

## Stage 2 Draft a case from a supplied payload

Support one documented Claude-compatible hook JSON shape. The helper writes a schema-1 custom-suite draft that the developer reviews and merges into their repository suite. This reduces JSON authoring while keeping intended behavior explicit.

### Input and output contract

- [x] Accept a local payload file containing `hook_event_name`, `tool_name`, `tool_input`, and optional `tool_response`. Support the existing `PreToolUse` and `PostToolUse` events only.
- [x] Require the author to supply a stable case ID, category, target policy, tier, and exact expected verdict. Use current coverage defaults; accept a source reference or explanation through the existing `note` field.
- [x] Map supported fields into a draft corpus. Preserve absence versus presence of `tool_response`, including `false` and `null`. Never derive the expectation from the observed policy decision.
- [x] Give field-specific diagnostics for malformed or unsupported inputs before writing anything. Reuse the corpus validation rules; extract a small shared validator only if the two entry points need it.
- [x] Improve the runner's existing corpus errors to name the case, field, and requirement. Preserve validation of the full suite before category filtering, engine calls, or report writes.
- [x] Write only to an explicit new draft path and refuse existing destinations, including aliases to inputs. Leave the supplied payload, suite, baseline, and reports intact. The helper does not call the engine or approve a baseline.
- [x] Explain omitted capture metadata. The existing runner supplies cwd at replay time and does not replay session state; an imported case must not silently claim to preserve either. Reject unsupported formats instead of guessing a universal trace mapping.

The separate `case.mjs` entry point takes `--input`, `--id`, `--cat`, `--target`, `--tier`, `--expect`, and `--out`, with optional `--coverage` and `--note`. The worked example and full contract are in [README.md](README.md#draft-a-case-from-a-hook-payload).

### Review and ordinary controls

- [x] Document a short path: supply an incident payload, choose the intended behavior, generate the draft, review or redact it, supply a nearby ordinary payload expected to receive `ALLOW`, and run the pair from the intended project directory.
- [x] Require an explicitly supplied ordinary counterpart for the worked example and pilot. Do not invent a harmless payload automatically or change the runner's support for attack-only and benign-only suites.
- [x] Verify the reviewed substitutions preserve the original failure condition. A desired behavior may still fail until the policy is fixed; keep that mismatch visible.
- [x] Cover both an unsafe allowance and an unwanted block with synthetic examples. Mark synthetic rehearsals separately from any actual incident.

**Acceptance:** produce runnable schema-1 drafts; preserve nested input values and response presence; reject invalid metadata without overwrites; and demonstrate that the resulting suite fails on the original undesired decision and passes after a controlled fix while its ordinary counterpart remains allowed. A saved failing baseline must not silence the expectation. A sentinel confirms imported commands and writes never execute.

**Likely files:** `case.mjs`, the current validation code in `run.mjs`, `test.mjs`, `examples/`, `README.md`, and the authoring section of `PILOT.md`.

**Format boundary:** upstream local decision logs lack tool inputs and responses, so they cannot supply complete replay cases. Start with explicitly supplied payloads. Cloud event export or additional trace formats require verified example schemas before adding an importer. [Pinned upstream log interface](https://github.com/FailproofAI/failproofai/blob/4fb46aa72a589f0522e5ef072e25da8b7f047bac/src/hooks/hook-activity-store.ts).

## Release checks for stages 1 and 2

- [x] Extend the existing `node test.mjs` checks for the new behavior and data-preservation failures. Keep existing verdict, input protection, and baseline checks passing.
- [x] Run the eight-job Ubuntu/macOS × Node 22/24 × engine 1.0.3/1.0.9 matrix. Retain built-in and custom all/default/isolated profiles. Generated example drafts must also pass through the runner.
- [x] Verify that all 99 built-in cases retain their reviewed decisions and category scores. Record changed expectations and their reasons before any baseline update; these stages should not require one.
- [x] Inspect summaries from both passing and intentionally failing runs, including missing results. Confirm that each artifact is attributable to its profile and current invocation.
- [x] Document the CLI, summary fields, compatibility boundaries, and unreleased changes in `CHANGELOG.md`.
- [x] Record one complete authoring rehearsal and an upgrade review using the new output. Publish only the claims supported by those checks.

All eight jobs passed on implementation commit `3f18938` in [the compatibility run](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37636042218). Its 48 measurements preserve every reviewed built-in decision and pass all 48 generated-case expectations. Local real-engine guard-disabling rehearsals and a published-pack upgrade replay are recorded in [the pilot validation](PILOT.md#implementation-validation-on-7-october-2026). Summary source text and failure behavior were checked; rendered GitHub UI inspection was unavailable in this session.

Technical checks and the documented workflow determine release readiness. A real production incident, independent adoption, and human time savings improve the value evidence after release; they do not hold this release open.

## Stage 3 Native Codex and configuration coverage

Extend the verified compatibility set from Claude-compatible calls to one pinned Codex adapter contract. Treat payload construction, verdict decoding, and baseline identity as one change.

- [x] Verify the upstream engine versions that support the required Codex inputs and responses. Record representative native fixtures and their sources before implementation.
- [x] Add explicit adapter selection with Claude as the backward-compatible default. Use the selected adapter's actual payload and response semantics. Unknown or unsupported responses must be invalid measurements, never implicit successes.
- [x] Record adapter identity in results and comparison inputs. Treat legacy results as Claude; reject accidental comparisons across adapters. Design cross-adapter experiments as explicitly paired cases, not ordinary baseline comparisons.
- [x] Cover shell commands, direct writes, edits, and multi-file patches. Include safe-only patches and patches where a protected path appears after an ordinary path, plus relevant quoting and path variants. Retain native payload evidence through evaluation.
- [x] Confirm whether schema 1 can faithfully represent the supported native calls. If it cannot, define a versioned extension and migration before changing the schema; do not force a lossy translation.
- [x] Record engine version, adapter, pack identifiers and hashes, mode, tested cwd, enabled selections where available, and fingerprints of explicitly selected configuration files. Exclude credentials and environment dumps. Label unverified configuration context clearly: file hashes identify inputs but do not prove the engine applied them.
- [x] Provide a reproducible recipe for two temporary, explicit configurations using the same suite and existing baseline comparison. Keep project parameters distinct from isolated policy defaults; preserve existing `--isolate` semantics.
- [x] Validate at least one nondefault policy parameter that changes a relevant decision, alongside an ordinary control. Follow version-pinned configuration precedence rather than guessing a merged configuration.

**Acceptance:** native fixtures reach the intended adapter without losing semantics; output decoding handles its real responses and errors; incompatible adapter comparisons fail clearly; configuration differences are visible; and ordinary operations stay represented beside risky ones. Existing Claude checks continue to pass. Add focused Codex CI jobs only for supported engine versions, with OS and Node coverage documented; do not silently multiply the full matrix by unsupported combinations.

The upstream report about Codex patches normalizing to `Edit` while a guard matched `Write` supplies a concrete test candidate. Reproduce it on explicitly pinned revisions before claiming a Chaos finding; an open PR's description alone is not independent validation. [Upstream PR 832](https://github.com/FailproofAI/failproofai/pull/832). Configuration parameters and scope rules are documented in [Failproof local configuration](https://docs.befailproof.ai/policies/local-configuration).

### Stage 3 validation — 8 October 2026

The [native fixtures](examples/codex-cases.json) preserve `Bash` and `apply_patch` command strings in schema 1. The [Codex hook contract](https://learn.chatgpt.com/docs/hooks) uses these native tool names; Failproof performs its own matcher normalization. The adapter rejects unsupported decisions and shapes. Post-tool blocking output is feedback (`FLAG`), not evidence that execution was prevented. Existing Claude decoding remains unchanged.

Local real-engine checks on 1.0.3, 1.0.9, and 1.0.10 with pack `06b802b63f4f` reproduce six desired protected-patch refusals returning `ALLOW`, including a protected path after an ordinary path. The 15-case diagnostic suite has nine matching expectations and six visible failures, with all six ordinary controls allowed and zero errors. These exploratory expectations stay `DENY`; no baseline or expectation was changed to hide them. This independently reproduces the candidate from upstream PR 832.

`test-codex-engine.mjs` also uses two explicit temporary homes and the same project cwd and suite to compare `block-read-outside-cwd.allowPaths`. The outside read changes `DENY` → `ALLOW`, creating one failed expectation and one regression; the ordinary repository read stays `ALLOW`. Configuration fingerprints match the supplied files, and source settings remain unchanged. This proves the tested parameter's effect; the general context record identifies sources only.

All offline checks pass. The six local Claude measurements (engines 1.0.3/1.0.9 × all/default/isolated) match every reviewed verdict and category score. The existing eight CI jobs remain intact; two focused Codex jobs add engine 1.0.10 on Ubuntu/Node 22 and macOS/Node 24. Their diagnostic check asserts the reviewed failures explicitly and keeps the failing policy reports in artifacts. All ten jobs pass after merge; the stage 3 pull request records artifact review.

Schema 1, default Claude behavior, and existing exit codes remain compatible. `adapter`, `runContext`, and `comparison.contextChanged` are additive. No schema migration or major-version requirement follows from this change. Release numbering and publication remain separate from implementation.

## Stage 4 Check suite sensitivity to weakened guards

Package the pilot's controlled guard-disabling rehearsal when a user needs to assess missing coverage. Start with a small explicit list of supported installed-pack policies.

- [ ] Require a passing unmodified suite before evaluating weakened configurations.
- [ ] Copy the selected test configuration into a temporary home, disable one supported guard at a time, verify that the change took effect, and rerun the same exact expectations.
- [ ] Report detected changes, missed changes, unsupported targets, and invalid measurements separately. An engine error is not a successful detection; another policy may continue to enforce the same behavior.
- [ ] Count detection only when a relevant case's exact expectation exposes the selected guard's weakening. An unrelated failure is not evidence, and an unchanged result with overlapping protection does not by itself prove inadequate coverage.
- [ ] Preserve the user's installed policies, settings, fixtures, and baselines, and remove temporary state on success or failure.
- [ ] Confirm detection of a known disabled guard, a missed change under a deliberately inadequate suite, an unsupported target, and an engine failure. Keep results separate from ordinary benchmark scores.

**Acceptance:** a developer can identify which selected weakened guards their suite catches and which require investigation. Describe results as sensitivity to these specific changes; do not advertise comprehensive attack resistance.

## Value measurements and scope limits

During actual use, record the incident or change reference, time to the first reviewed runnable pair, authoring and maintenance effort, whether the report supported a correct upgrade decision, and use on a subsequent change. Record manual checks or human minutes saved only when observed or explicitly estimated, with the method stated. Keep agent reading time and CI duration separate. Extend [PILOT.md](PILOT.md) as evidence arrives.

The initial adopter is a developer maintaining Failproof policies for a repository that uses a supported coding agent. The main value hypothesis is less work reproducing guard failures and reviewing subsequent changes. Existing trials establish the technical workflow; independent recurring demand still needs validation.

Automatic monitoring, broad trace import, a hosted dashboard, automatic policy repair, a generic plugin system, and live command execution remain outside this plan's first releases. Upstream already offers [local audit replay](https://docs.befailproof.ai/audits/local-audit) and [individual policy tests](https://docs.befailproof.ai/policies/test). Focus the next implementation on reviewed repository fixtures and clear upgrade decisions. This follows the recommendation to derive evaluations from actual failures and manual checks in [Anthropic's evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).

## Completed v2.0.0 implementation

The following sections retain the original release plan and its completion evidence. Their first-release scope describes v2.0.0.

Let teams check policy changes against their own tool calls before merging. A reported unsafe allowance or unwanted block becomes a reviewed test that runs on every subsequent change.

The v2.0.0 release adds JSON suites and explicit expected decisions to the existing runner. This major product milestone preserves the v1.2 CLI and schema-1 compatibility. Human time savings and independent user feedback are post-release validation work.

### Product hypothesis

Teams using Claude-compatible Failproof hooks will get recurring value from testing their own commands, paths, and policy configuration. The value to validate is fewer repeated failures and less manual checking during policy updates.

Anthropic recommends turning actual failures into regression tests and testing legitimate work alongside unsafe actions. Failproof already provides dashboard backtesting and local policy tests; Promptfoo also supports regressions based on agent traces. The proposed workflow focuses on reviewed fixtures stored with the team's repository and checked in CI. [Anthropic guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents), [Failproof policy testing](https://docs.befailproof.ai/policies/test), [Promptfoo agent testing](https://www.promptfoo.dev/docs/red-team/agents/).

### First release scope

- Add `--corpus <file.json>` to load a team's suite in place of the built-in corpus.
- Reuse hook invocation, verdict classification, category summaries, baseline comparison, and report generation.
- Require an exact expected verdict for every custom case. This catches an existing failure even when the saved baseline contains the same failure.
- Run against the installed configuration from the team's project directory. Each fixture is an independent tool call using the runner's cwd.
- Support installed pack targets through the existing `--isolate` mechanism. Standalone custom policy files use combined mode; isolation continues to require an unambiguous installed pack target.
- Use manually reviewed fixtures with synthetic or redacted data. Review substitutions so they preserve the condition the policy needs to detect. Reports contain fixture payloads, so the example and documentation must make this explicit.

Automatic session capture, trace import, additional agent adapters, dashboards, and live tool execution can follow demonstrated pilot needs. The first release measures per-call policy decisions.

### Suite and CLI contract

Use a versioned JSON object containing `schemaVersion: 1` and a nonempty `cases` array. Reuse existing case fields: `id`, `cat`, `target`, `tier`, `event`, `tool_name`, `tool_input`, optional `tool_response`, `coverage`, and `note`. Add required `expect`.

`expect` accepts `ALLOW`, `DENY`, `ASK`, `FLAG`, or `INSTRUCT`. Matching is exact: a team that requires a refusal can distinguish `DENY` from a human approval prompt. Benign cases require `ALLOW`. Attack coverage defaults to `exploratory`; `documented` requires review against the tested policy's declared scope. Benign coverage is `benign`.

Custom category names come from the suite. Accept attack-only and benign-only suites. Validate the complete suite before applying `--cat`; a malformed case cannot be hidden by a filter. Reject duplicate IDs, unsupported schemas, invalid fields, missing expectations, and empty selections before invoking the engine or replacing reports. Protect corpus files from output overwrites, including symlink and hard-link aliases.

Proposed usage:

```bash
# Inspect the team's expected decisions.
node run.mjs --corpus examples/team-cases.json

# Gate on expectations without a saved baseline.
node run.mjs --corpus examples/team-cases.json --ci

# Also check changes against a reviewed previous run.
node run.mjs --corpus examples/team-cases.json --baseline team-baseline.json --ci
```

For custom suites, `--ci` can run without a baseline because every case has an expectation. Built-in suites retain the existing requirement for `--baseline` with `--ci`. Inspection runs report expectation failures without gating; invalid input and engine errors always fail.

### Gate and reporting behavior

| Exit | Custom suite behavior |
|------|-----------------------|
| 0 | Valid inspection run; with `--ci`, every expectation passes and any supplied baseline comparison passes |
| 1 | With `--ci`, an expectation fails or the baseline detects a regression |
| 2 | Invalid input, engine error, or incomplete baseline comparison in CI |

Exit 2 takes precedence over exit 1. A saved baseline cannot override a failed expectation. Changes to a case's expectation require review when comparing with a baseline, just like changed payloads. Baseline validation must support suites containing only benign cases.

Keep result schema 1 and existing field meanings. Custom rows include `expect`; add an `expectations` summary with total, passed, failed, and mismatches containing case ID, expected verdict, and actual verdict. Show mismatches and policy reasons in console output and `REPORT.md`. Escape custom metadata as text in reports. Keep attack allowances, unwanted blocks, notices, and engine errors visible separately. Describe custom coverage labels in terms of the reviewed suite rather than attributing them to the pinned public pack.

### Implementation order

#### 1 Define the suite and example

- [x] Add one small synthetic suite under `examples/`, pairing a protected file read with an allowed public file read.
- [x] Document required fields, exact expectations, cwd behavior, and the proposed commands in `README.md`.
- [x] Keep suite loading in `run.mjs` with Node's standard library.

Done when the example describes a useful test and the input rules are unambiguous.

#### 2 Load suites and check expectations

- [x] Add JSON loading and validation before engine calls and output writes.
- [x] Route selected cases through the existing runner.
- [x] Add expectation reporting and CI gating, including baseline review of changed expectations.
- [x] Extend the baseline reader to accept nonempty suites with zero attack rows.

Done when an unsafe allowance and an unwanted block both fail CI, including when their actual decisions already appear in the saved baseline.

#### 3 Verify compatibility and failure handling

Extend the existing fake-engine checks in `test.mjs`:

- [x] Matching expectations pass; mismatches fail; engine errors remain invalid measurements.
- [x] Exact verdict checks distinguish `DENY` and `ASK`, and blocking decisions from notices.
- [x] Attack-only and benign-only suites work with category filtering and baselines.
- [x] Malformed suites, duplicate IDs, missing expectations, and output aliases preserve existing files and fail before engine invocation.
- [x] New, changed, and removed cases require baseline review, including changed expectations.
- [x] Literal command and write payloads remain data; a sentinel check confirms they are never executed.
- [x] Custom metadata and payload text render safely in reports, including Markdown delimiters and newlines.
- [x] Existing built-in and legacy-baseline checks still pass.

Then run the existing eight-job matrix: Ubuntu/macOS, Node 22/24, and engines 1.0.3/1.0.9. Continue validating all/default/isolated configurations and include the synthetic custom suite in each profile, preserving separate report artifacts. Confirm the 99 built-in cases retain their reviewed verdicts and category scores.

Done when all jobs pass and each supported profile produces attributable reports.

Validation completed on [the eight-job branch run](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37435918835) and [the pull request run](https://github.com/pratik-mahalle/failproof-chaos/actions/runs/37436041315). All jobs passed. Review of the branch run's eight artifact bundles confirmed 48 measurements and 96 report files: every built-in decision, classification, and category score matched its reviewed snapshot, and all 48 custom decisions matched their expectations.

#### 4 Validate the workflow in use

- [x] Prepare a project-root CI recipe and a short guide for converting an incident into a fixture.
- [x] Prepare, validate, and merge suites in three repositories chosen from the owner's GitHub profile, with at least five legitimate calls each and pinned CI integrations.
- [x] Verify that deliberately disabling a guard in each temporary configuration fails its suite. Rehearse the existing unwanted block and confirm that a saved failing baseline cannot hide it.
- [x] Record initial value: first runs on main, measured CI times, controlled regressions caught, the known unwanted block, and the shared setup defect fixed.
- [x] Reuse the suites during a real published engine and policy update in all three repositories, preserving existing decisions and reviewing new cleanup expectations.
- [x] Assess developer usefulness, compare agent review time for JSON and Markdown outputs, and remove manual result matching by generating reports with the existing baseline option. Record the distinction from human time savings.

The initial three-repository trial passed all 21 expectations on both local engine 1.0.3 and CI engine 1.0.9. All three controlled regressions failed as intended. The PRs, source pins, configuration, and limitations are recorded in [PILOT.md](PILOT.md). One owner's seed suites do not establish independent team adoption or recurring value. The follow-up published dependency update passes all 27 expectations in both combined and isolated modes; the new cleanup behavior is advisory and remains distinct from refusals. Internal reuse is recorded in the pilot guide.

For the initial cohort, at least two repositories should reuse the suite on another change and the owner should report reduced manual checking or an actionable finding. Broader demand still needs independent team feedback. If setup or fixture authoring prevents repeat use, improve that step before expanding coverage. Ask about willingness to pay after users have used the workflow.

### Release criteria

- [x] CLI documentation, result fields, failure behavior, and example match the implementation.
- [x] All compatibility and matrix checks pass.
- [x] Validate internal reuse during a real published dependency update and document its scope and limitations.
- [x] Review the additive contract changes and record them in `CHANGELOG.md` for v2.0.0.

The initial trial and the follow-up dependency upgrade are merged, with policy runs on main passing. Initial measurements and internal reuse are recorded in [PILOT.md](PILOT.md). Release is based on the verified runner contract, compatibility checks, and repository trials. Human timing and feedback remain unmeasured and are no longer release gates.

### Post-release validation

- [ ] Capture a real incident from live hook use.
- [ ] Measure human authoring and review effort and manual checks saved.
- [ ] Collect user feedback on recurring usefulness and independent team adoption.
