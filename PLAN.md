# Custom workflow regression tests

Let teams check policy changes against their own tool calls before merging. A reported unsafe allowance or unwanted block becomes a reviewed test that runs on every subsequent change.

The first release adds JSON suites and explicit expected decisions to the existing runner. Proposed release: v1.3, subject to the compatibility checks below.

## Product hypothesis

Teams using Claude-compatible Failproof hooks will get recurring value from testing their own commands, paths, and policy configuration. The value to validate is fewer repeated failures and less manual checking during policy updates.

Anthropic recommends turning actual failures into regression tests and testing legitimate work alongside unsafe actions. Failproof already provides dashboard backtesting and local policy tests; Promptfoo also supports regressions based on agent traces. The proposed workflow focuses on reviewed fixtures stored with the team's repository and checked in CI. [Anthropic guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents), [Failproof policy testing](https://docs.befailproof.ai/policies/test), [Promptfoo agent testing](https://www.promptfoo.dev/docs/red-team/agents/).

## First release scope

- Add `--corpus <file.json>` to load a team's suite in place of the built-in corpus.
- Reuse hook invocation, verdict classification, category summaries, baseline comparison, and report generation.
- Require an exact expected verdict for every custom case. This catches an existing failure even when the saved baseline contains the same failure.
- Run against the installed configuration from the team's project directory. Each fixture is an independent tool call using the runner's cwd.
- Support installed pack targets through the existing `--isolate` mechanism. Standalone custom policy files use combined mode; isolation continues to require an unambiguous installed pack target.
- Use manually reviewed fixtures with synthetic or redacted data. Review substitutions so they preserve the condition the policy needs to detect. Reports contain fixture payloads, so the example and documentation must make this explicit.

Automatic session capture, trace import, additional agent adapters, dashboards, and live tool execution can follow demonstrated pilot needs. The first release measures per-call policy decisions.

## Suite and CLI contract

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

## Gate and reporting behavior

| Exit | Custom suite behavior |
|------|-----------------------|
| 0 | Valid inspection run; with `--ci`, every expectation passes and any supplied baseline comparison passes |
| 1 | With `--ci`, an expectation fails or the baseline detects a regression |
| 2 | Invalid input, engine error, or incomplete baseline comparison in CI |

Exit 2 takes precedence over exit 1. A saved baseline cannot override a failed expectation. Changes to a case's expectation require review when comparing with a baseline, just like changed payloads. Baseline validation must support suites containing only benign cases.

Keep result schema 1 and existing field meanings. Custom rows include `expect`; add an `expectations` summary with total, passed, failed, and mismatches containing case ID, expected verdict, and actual verdict. Show mismatches and policy reasons in console output and `REPORT.md`. Escape custom metadata as text in reports. Keep attack allowances, unwanted blocks, notices, and engine errors visible separately. Describe custom coverage labels in terms of the reviewed suite rather than attributing them to the pinned public pack.

## Implementation order

### 1 Define the suite and example

- [x] Add one small synthetic suite under `examples/`, pairing a protected file read with an allowed public file read.
- [x] Document required fields, exact expectations, cwd behavior, and the proposed commands in `README.md`.
- [x] Keep suite loading in `run.mjs` with Node's standard library.

Done when the example describes a useful test and the input rules are unambiguous.

### 2 Load suites and check expectations

- [x] Add JSON loading and validation before engine calls and output writes.
- [x] Route selected cases through the existing runner.
- [x] Add expectation reporting and CI gating, including baseline review of changed expectations.
- [x] Extend the baseline reader to accept nonempty suites with zero attack rows.

Done when an unsafe allowance and an unwanted block both fail CI, including when their actual decisions already appear in the saved baseline.

### 3 Verify compatibility and failure handling

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

### 4 Validate the workflow with teams

- [x] Prepare a project-root CI recipe and a short guide for converting an incident into a fixture.
- [ ] Pilot with three teams, each supplying one real incident and at least five legitimate tool calls.
- [ ] Have each team use the suite during its next policy change.
- [ ] Record time to first passing run, review effort, actionable findings, and repeat use on another change. Include a deliberately changed policy in the pilot to verify that the gate detects a regression.

Proposed continuation criterion: at least two teams reuse the suite on another change and report reduced manual checking or an actionable finding. If setup or fixture authoring prevents repeat use, improve that step before expanding coverage. Ask about willingness to pay after teams have used the workflow.

## Release criteria

- [x] CLI documentation, result fields, failure behavior, and example match the implementation.
- [x] All compatibility and matrix checks pass.
- [ ] Pilot feedback supports recurring use.
- [x] Review the additive contract changes and record them in `CHANGELOG.md` before preparing v1.3.

The next step is running the three-team pilot described in [PILOT.md](PILOT.md). Release remains conditional on its results.
