# Pilot custom workflow tests

Use a team's real policy change to test whether reviewed tool-call fixtures reduce manual checking or reveal a useful regression. Start with three teams using Claude-compatible Failproof hooks.

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
      FAILPROOFAI_HOME: ${{ runner.temp }}/failproof-team
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

Continue investing when at least two of the three teams reuse the suite and report less manual checking or an actionable finding. Improve fixture authoring or setup first if either prevents repeat use. Discuss willingness to pay after teams have used the workflow. Pilot outcomes and demand remain to be measured.
