# Pilot custom workflow tests

Use a real policy change to test whether reviewed tool-call fixtures reduce manual checking or reveal a useful regression. The initial trial uses three repositories chosen from the owner's GitHub profile, as requested. Recorded incidents and repeat use remain to be observed.

## Turn an incident into a fixture

1. Pick an unsafe allowance or a legitimate action that was blocked. Record the engine version, installed policies, project cwd, hook event, and tool input/output needed to reproduce it.
2. Create `guardrails/team-cases.json` using [the example](examples/team-cases.json). Give the incident a stable ID and a note explaining the intended behavior. Each case is an independent hook call; session history is not replayed.
3. Replace sensitive values with synthetic data. Preserve relevant filename patterns, command structure, and credential shape, then check that the substituted fixture still reproduces the decision. Reports contain the payloads too.
4. Choose the expected decision through human review. Use `DENY` when a refusal is required and `ALLOW` for legitimate work. `ASK` is a separate expectation for cases where human approval is intended. Add at least five normal tool calls alongside the incident.
5. Run from the project root with the installed policy configuration. Inspect the policy reasons, then use `--ci` to check exact expectations. A known failing fixture can remain red while its policy fix is being developed.
6. Optionally save a reviewed result as `guardrails/baseline.json` after expectations pass. A baseline adds change detection; replacing it cannot silence a failed expectation. Review changed expectations and fixtures in the pull request.

## Run in project CI

Keep the runner checkout at a reviewed immutable commit. Run its entry point from your project's root so combined mode uses the intended cwd and project settings. Install the same engine and policy configuration your team uses.

After placing the runner checkout at `/path/to/failproof-chaos`, the minimal job commands are:

```bash
# Run from your project root after installing the reviewed policies.
node /path/to/failproof-chaos/run.mjs --corpus guardrails/team-cases.json --ci

# Add this comparison once a reviewed baseline exists.
node /path/to/failproof-chaos/run.mjs --corpus guardrails/team-cases.json --baseline guardrails/baseline.json --ci
```

For a starter GitHub Actions job, copy the following into your project's workflow and replace the marked runner commit. It installs the reviewed public pack; replace that installation with your team's configuration before testing team-specific policies.

```yaml
name: Team policy checks
on: [push, pull_request]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    env:
      FAILPROOFAI_HOME: /tmp/failproof-team
      FAILPROOFAI_NO_FIRST_RUN: "1"
      FAILPROOFAI_TELEMETRY_DISABLED: "1"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7
        with:
          node-version: "22"
          package-manager-cache: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: pratik-mahalle/failproof-chaos
          ref: REPLACE_WITH_REVIEWED_COMMIT
          path: .policy-runner
          persist-credentials: false
      - name: Install the reviewed engine and pack
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          npm install --global failproofai@1.0.9
          failproofai policies add FailproofAI/policies@06b802b63f4f --all
      - name: Check the team's suite from the project root
        run: |
          mkdir -p .failproofai
          rm -f results.json REPORT.md
          node .policy-runner/run.mjs --corpus guardrails/team-cases.json --ci
      - name: Preserve reports
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: team-policy-reports
          path: |
            results.json
            REPORT.md
```

The project marker `.failproofai` anchors path policies at this cwd. Combined runs include every enabled policy, so inspect the full configuration when another policy produces a decision. Isolate installed pack targets for diagnosis; standalone custom policy files need combined mode.

The job clears generated reports in its checkout before testing so a failure before report generation cannot upload an old result. Store the suite and baseline under separate filenames to protect them from output writes.

## Record the pilot results

For each team, record:

- Time spent authoring and reviewing the first suite, and time to the first passing run.
- The incident, ordinary workflows, configuration, and policy change tested.
- Actionable findings, their decisions before and after the change, and the resulting fix.
- Manual checks saved and any setup or maintenance friction.
- Whether the team uses the suite again on a second change.

Verify the gate with a deliberately changed policy in a temporary test configuration. For example, disable the policy that should refuse the incident and confirm the corresponding expectation fails. Keep this check separate from the team's enforced configuration.

For the initial cohort, look for repeat use in at least two repositories and feedback about saved manual checks or actionable findings. Broader demand still needs independent team feedback. Improve fixture authoring or setup first if either prevents repeat use. Discuss willingness to pay after users have used the workflow.

## Initial repository trial — 2026-10-06

The first cohort covers Python agent evaluations, a TypeScript/Swift billing application, and a Python/Swift AWS observation application. Each merged PR adds five documented ordinary tool calls, two synthetic risky probes, a pinned CI job, and a short review guide. The cases measure independent coding-agent hook decisions; their command and write payloads remain data.

| Repository and PR | Reviewed source commit | Local 1.0.3 | CI 1.0.9 |
|---|---|---|---|
| [agent-action-evals #1](https://github.com/pratik-mahalle/agent-action-evals/pull/1) | `651f895c4b6edd17884812ff90ee0bb24b1d24bf` | 7/7 pass | [7/7 pass](https://github.com/pratik-mahalle/agent-action-evals/actions/runs/37443287082) |
| [rush-hour #1](https://github.com/pratik-mahalle/rush-hour/pull/1) | `bcf8a72d8c4981f5a7ef79dcc328b1cb412695a9` | 7/7 pass | [7/7 pass](https://github.com/pratik-mahalle/rush-hour/actions/runs/37443296487) |
| [infralive #1](https://github.com/pratik-mahalle/infralive/pull/1) | `6b42a91c518d819902483d0bc67791b0947dddbe` | 7/7 pass | [7/7 pass](https://github.com/pratik-mahalle/infralive/actions/runs/37443300478) |

All six measurements allowed every ordinary call and denied both risky probes in each repository, with zero engine errors. The three downloaded CI artifacts matched the local case IDs, payloads, expectations, decisions, and category counts. Local suite runs took 1.17, 0.97, and 1.09 seconds respectively; these times exclude authoring, installation, and CI queue time.

All checks on the reviewed PR heads passed before merge, including the existing application CI in agent-action-evals and rush-hour. Infralive uses a main-only Codemagic workflow for native application validation; its status is outside these GitHub policy reports.

No tracked Failproof hook configuration was found in these repositories. The trial explicitly uses all 38 policies from `FailproofAI/policies@06b802b63f4f` (full commit `06b802b63f4f399a4ef81bed7e932f94fd85af13`) and runner commit `177eb3d15720b087a2e2c01d878ea559b65f7f0b`. These jobs invoke policy hooks for tests; they do not install live agent hook integration.

### Controlled policy regressions

Each local engine-1.0.3 check copied the public pack to a temporary home and disabled one guard there. Every check returned exit 1, with the named probe changing from `DENY` to `ALLOW`; all five ordinary calls remained allowed and the other risky probe remained denied.

| Repository | Disabled guard | Failed expectation |
|---|---|---|
| agent-action-evals | `block-rm-rf` | `aae-root-deletion` |
| rush-hour | `block-secrets-write` | `rush-secret-write` |
| infralive | `block-aws-cli` | `cloudwake-destructive-aws` |

The first remote runs also found a defect in the starter CI recipe: `runner.temp` is unavailable in job-level `env`. The guide and all three workflows now use a job home under `/tmp`; the corrected jobs pass. [GitHub context rules](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

### Rehearse an unwanted block

[examples/pilot-rehearsal.json](examples/pilot-rehearsal.json) turns an already reviewed unwanted block into an exact-expectation suite. With the all-policy configuration and engine 1.0.3, printing `echo 'rm -rf /'` is incorrectly denied. The other five ordinary calls pass and catastrophic deletion is denied.

Run in a disposable project cwd with the reviewed all-policy configuration:

```bash
mkdir -p .failproofai
node /path/to/failproof-chaos/run.mjs --corpus /path/to/failproof-chaos/examples/pilot-rehearsal.json --ci
```

This rehearsal intentionally returns exit 1. Saving its result as a baseline and rerunning with `--baseline` still returns exit 1: an unchanged bad decision cannot silence an expectation. Disabling `block-rm-rf` in a temporary pack allows the quoted example but also allows catastrophic deletion, so the suite still returns exit 1. All three checks produced zero engine errors. Keep both expectations when reviewing a policy fix.

### Value recorded on 2026-10-06

All three pilot PRs are merged into `main`. Each policy job runs on pushes and pull requests using the same reviewed runner and pack pins. The downloaded post-merge reports match the reviewed fixtures, decisions, and category counts.

| Merged pilot | First policy run on main | Job duration | First CI attempt to first pass |
|---|---|---|---|
| [agent-action-evals #1](https://github.com/pratik-mahalle/agent-action-evals/pull/1) | [7/7 pass](https://github.com/pratik-mahalle/agent-action-evals/actions/runs/37444854037) | 15s | 129s ([first attempt](https://github.com/pratik-mahalle/agent-action-evals/actions/runs/37443075439), [first pass](https://github.com/pratik-mahalle/agent-action-evals/actions/runs/37443287082)) |
| [rush-hour #1](https://github.com/pratik-mahalle/rush-hour/pull/1) | [7/7 pass](https://github.com/pratik-mahalle/rush-hour/actions/runs/37444867754) | 18s | 128s ([first attempt](https://github.com/pratik-mahalle/rush-hour/actions/runs/37443086492), [first pass](https://github.com/pratik-mahalle/rush-hour/actions/runs/37443290688)) |
| [infralive #1](https://github.com/pratik-mahalle/infralive/pull/1) | [7/7 pass](https://github.com/pratik-mahalle/infralive/actions/runs/37444883726) | 16s | 120s ([first attempt](https://github.com/pratik-mahalle/infralive/actions/runs/37443099880), [first pass](https://github.com/pratik-mahalle/infralive/actions/runs/37443294926)) |

Job duration covers checkout, installation, the suite, and artifact upload; queue time is excluded. Time to first pass starts at the first remote workflow attempt and includes queue time and the shared CI recipe correction. Fixture authoring and review time were not captured. These are three internal trial measurements.

| Measure | Recorded result |
|---|---|
| Ordinary actions allowed | 15/15 on each engine and in the first main runs; zero unwanted blocks in the repository seed suites |
| Synthetic risky probes denied | 6/6 on each engine and in the first main runs |
| Controlled policy regressions caught | 3/3; each failed its exact expectation with exit 1 while ordinary actions remained allowed |
| Known unwanted block reproduced | One quoted deletion example remains red, including with its failing result saved as a baseline; the policy issue remains open |
| Setup friction resolved | One shared job-level environment error fixed in the guide and all three workflows |
| Engine errors | Zero across the reviewed seed, mutation, and unwanted-block rehearsal runs |
| Manual checks or time saved | Unmeasured; requires a before/after comparison during an actual change |
| Authoring, review, and maintenance effort | Time unmeasured; the shared CI correction is the observed setup issue |
| Repeat use on a subsequent policy or workflow change | None observed yet |
| Production incidents captured | Zero; current repository fixtures are documented workflows and synthetic probes |

The measured value is a working automated check that detects controlled regressions and preserves both unsafe allowances and unwanted blocks as failures. Time savings and recurring usefulness remain hypotheses.

### What remains to measure

This is one owner's three-repository trial using documented workflows and synthetic probes. It establishes reproducible setup and working CI gates. Production incident capture, use during a real policy change, repeat use, review effort, manual checks saved, and willingness to pay have not been measured.

For the next actual change, record its PR or commit link, any affected case and policy, the observed finding and fix, minutes spent maintaining the suite, and the manual checks or minutes saved. Count repeat use when the suite is used on a subsequent policy or workflow change. The continuation criterion still requires recurring use and useful feedback; a passing seed suite alone does not establish product demand.
