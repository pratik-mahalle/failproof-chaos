// CLI boundaries: native payload fidelity, adapter identity, and invalid comparisons.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const work = mkdtempSync(join(tmpdir(), "chaos-adapter-cli-"));
const runner = fileURLToPath(new URL("./run.mjs", import.meta.url));
const engine = join(work, "engine.mjs");
const suite = join(work, "suite.json");
const baseline = join(work, "baseline.json");
const result = () => JSON.parse(readFileSync(join(work, "results.json"), "utf8"));
const native = { id: "patch", cat: "patch", tier: "benign", target: "block-env-files", event: "PreToolUse",
  tool_name: "apply_patch", tool_input: { command: "*** Begin Patch\n*** Add File: docs/demo.txt\n+$(touch DO-NOT-EXECUTE)\n*** End Patch", nested: { args: [false, null] } }, expect: "ALLOW" };
function run(args = [], response = "") {
  return spawnSync(process.execPath, [runner, "--corpus", suite, ...args], { cwd: work, encoding: "utf8",
    env: { ...process.env, FAILPROOFAI_BIN: engine, FAILPROOFAI_HOME: join(work, "home"),
      FAILPROOFAI_PACK_DIR: join(work, "home", "policies", "packs"), GITHUB_STEP_SUMMARY: join(work, "summary.md"), RESPONSE: response } });
}
try {
  mkdirSync(join(work, ".failproofai"));
  writeFileSync(engine, `#!${process.execPath}
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
appendFileSync('calls.txt', process.argv.slice(2).join(' ')+'\\n');
if (process.argv[2] === '--version') { console.log('1.0.10'); process.exit(0); }
if (process.argv[2] === 'policies') { console.log('test pack'); process.exit(0); }
writeFileSync('capture.json', readFileSync(0, 'utf8'));
process.stdout.write(process.env.RESPONSE);
`, { mode: 0o755 });
  writeFileSync(suite, JSON.stringify({ schemaVersion: 1, cases: [native] }));
  assert.equal(run(["--adapter", "codex", "--ci"]).status, 0);
  assert.equal(result().adapter, "codex");
  assert.equal(result().runContext.adapter, "codex");
  assert.deepEqual(JSON.parse(readFileSync(join(work, "capture.json"))).tool_input, native.tool_input);
  assert.match(readFileSync(join(work, "calls.txt"), "utf8"), /--hook PreToolUse --cli codex/);
  assert.match(readFileSync(join(work, "summary.md"), "utf8"), /adapter: \*\*codex\*\*/);
  writeFileSync(baseline, JSON.stringify(result()));
  assert.equal(run(["--adapter", "codex", "--baseline", baseline, "--ci"]).status, 0);
  assert.equal(result().comparison.contextChanged, false);
  writeFileSync(join(work, ".failproofai", "policies-config.json"), '{"params":{"sample":"DO-NOT-COPY"}}');
  assert.equal(run(["--adapter", "codex", "--baseline", baseline, "--ci"]).status, 0);
  assert.equal(result().comparison.contextChanged, true);
  assert.doesNotMatch(JSON.stringify(result().runContext), /DO-NOT-COPY/);
  const previous = result();
  for (const prior of [{ ...previous, adapter: "claude" }, { ...previous, adapter: undefined }, previous.controls]) {
    writeFileSync(baseline, JSON.stringify(prior));
    const calls = readFileSync(join(work, "calls.txt"), "utf8");
    assert.equal(run(["--adapter", "codex", "--baseline", baseline, "--ci"]).status, 2);
    assert.equal(readFileSync(join(work, "calls.txt"), "utf8"), calls);
    assert.deepEqual(result(), previous);
  }
  const calls = readFileSync(join(work, "calls.txt"), "utf8");
  assert.equal(run(["--adapter", "unknown"]).status, 2);
  assert.equal(readFileSync(join(work, "calls.txt"), "utf8"), calls);
  const noSuite = spawnSync(process.execPath, [runner, "--adapter", "codex"], { cwd: work, encoding: "utf8" });
  assert.equal(noSuite.status, 2);
  assert.match(noSuite.stderr, /requires --corpus/);
  assert.equal(run(["--adapter", "codex"], '{"hookSpecificOutput":{"permissionDecision":"ask"}}').status, 2);
  writeFileSync(suite, JSON.stringify({ schemaVersion: 1, cases: [{ ...native, tier: "direct", event: "PostToolUse",
    expect: "FLAG", tool_response: false }] }));
  assert.equal(run(["--adapter", "codex", "--ci"], '{"decision":"block","reason":"feedback"}').status, 0);
  assert.equal(result().summary.held, 0);
  assert.equal(result().summary.flagged, 1);
  assert.equal(JSON.parse(readFileSync(join(work, "capture.json"))).tool_response, false);
  // Legacy baselines continue to mean Claude, including legacy arrays.
  assert.equal(run([], '{"decision":"block","reason":"feedback"}').status, 0);
  assert.equal(result().adapter, "claude");
  writeFileSync(baseline, JSON.stringify(result().results));
  assert.equal(run(["--baseline", baseline], '{"decision":"block","reason":"feedback"}').status, 0);
  assert.equal(result().comparison.contextChanged, null);
  console.log("Codex CLI checks passed: native input, baseline compatibility, context, and post-tool feedback.");
} finally { rmSync(work, { recursive: true, force: true }); }
