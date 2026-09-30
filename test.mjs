// Runnable CLI check; all engine responses are fake and commands never execute.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CORPUS } from "./corpus.mjs";

const work = mkdtempSync(join(tmpdir(), "failproof-check-"));
const engine = join(work, "engine.mjs");
const baseline = join(work, "baseline.json");
const runner = fileURLToPath(new URL("./run.mjs", import.meta.url));
const resultsFile = join(work, "results.json");
const read = () => JSON.parse(readFileSync(resultsFile, "utf8"));
function run(args = ["--cat", "sudo"], mode = "normal", binary = engine) {
  return spawnSync(process.execPath, [runner, ...args], {
    cwd: work, env: { ...process.env, FAILPROOFAI_BIN: binary, CHECK_MODE: mode },
    encoding: "utf8", timeout: 30000,
  });
}

try {
  writeFileSync(engine, `#!${process.execPath}
import { readFileSync } from 'node:fs';
const mode = process.env.CHECK_MODE;
if (process.argv[2] === '--version') { console.log('9.8.7'); process.exit(0); }
if (process.argv[2] === 'policies') { console.log('test policies: pack@abc, 3 enabled'); process.exit(0); }
const input = JSON.parse(readFileSync(0, 'utf8'));
const command = input.tool_input.command;
const emit = (out) => { console.log(JSON.stringify(out)); process.exit(0); };
if (mode === 'crash') { console.error('engine crashed'); process.exit(1); }
if (mode === 'signal') { process.kill(process.pid, 'SIGTERM'); }
if (mode === 'exit2') { console.error('blocked by hook'); process.exit(2); }
if (mode === 'bad-json') { console.log('oops'); process.exit(0); }
if (mode === 'null') emit(null);
if (mode === 'empty-object') emit({});
if (mode === 'bad-context') emit({ hookSpecificOutput: { additionalContext: 42 } });
if (mode === 'unknown') emit({ decision: 'surprise' });
if (mode === 'fail-closed') emit({ decision: 'block', reason: 'failproofai could not evaluate this call and is failing closed' });
if (mode === 'pack-failure') emit({ hookSpecificOutput: { permissionDecision: 'deny', permissionDecisionReason: 'Blocked because a policy pack this machine is configured to enforce is not running' } });
if (mode === 'all-allow') process.exit(0);
if (mode === 'all-deny') emit({ decision: 'block', reason: 'blocked' });
if (input.hook_event_name === 'PostToolUse') emit({ hookSpecificOutput: { additionalContext: 'secret detected' } });
if (command === 'sudo rm /var/log/syslog') {
  if (mode === 'slip') process.exit(0);
  if (mode === 'warn') emit({ hookSpecificOutput: { additionalContext: 'please stop' } });
  emit({ hookSpecificOutput: { permissionDecision: mode === 'ask' ? 'ask' : 'deny', permissionDecisionReason: 'guard' } });
}
if (command === 'command sudo apt install x') emit({ hookSpecificOutput: { additionalContext: 'please stop' } });
process.exit(0);
`, { mode: 0o755 });

  assert.equal(run([]).status, 0);
  const initial = read();
  assert.equal(initial.results.length, CORPUS.length);
  assert.equal(initial.engine.version, "9.8.7");
  assert.match(initial.policies, /pack@abc/);
  assert.equal(initial.summary.held, 1);
  assert.equal(initial.summary.flagged, 6);
  assert.equal(initial.summary.allowed, 38);
  assert.equal(initial.results.find((r) => r.id === "sec-01").verdict, "FLAG");
  assert.equal(initial.results.find((r) => r.id === "sec-01").held, false);
  assert.equal(initial.results.find((r) => r.id === "pkg-01").held, false);
  writeFileSync(baseline, JSON.stringify(initial));
  const ci = ["--cat", "sudo", "--baseline", baseline, "--ci"];
  assert.equal(run(ci).status, 0); // known ALLOW and warning do not fail CI
  assert.deepEqual(read().summary, { total: 3, held: 1, flagged: 1, allowed: 1, errors: 0, evasionsHeld: 0, evasionsTotal: 2 });
  assert.equal(run(ci, "slip").status, 1);
  assert.deepEqual(read().comparison.changes, [{ id: "sudo-01", before: "DENY", after: "ALLOW", kind: "REGRESSION" }]);
  assert.equal(run(ci, "warn").status, 1); // block -> warning is a regression
  assert.equal(run(ci, "all-allow").status, 1); // warning -> allow also regresses
  assert.equal(read().comparison.changes.length, 2);
  assert.equal(run(ci, "ask").status, 0);
  assert.equal(run(ci, "all-deny").status, 0);
  assert.equal(read().comparison.changes.every((r) => r.kind === "IMPROVEMENT"), true);
  assert.equal(run(ci.slice(0, -1), "slip").status, 0); // comparison without gating
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /<<'PAYLOAD'/);
  assert.deepEqual(JSON.parse(readFileSync(baseline, "utf8")), initial);

  for (const mode of ["crash", "signal", "bad-json", "null", "empty-object", "bad-context", "unknown", "fail-closed", "pack-failure"]) {
    assert.equal(run(ci, mode).status, 2, mode);
    assert.equal(read().summary.errors, 3, mode);
    assert.equal(read().summary.allowed, 0, mode);
    assert.equal(read().comparison.changes.length, 0, mode);
  }
  assert.equal(run(ci, "exit2").status, 0);
  assert.equal(read().summary.held, 3);

  const legacy = initial.results.map((r) => ({ ...r, verdict: r.verdict === "FLAG" ? "SANITIZE" : r.verdict, held: true }));
  writeFileSync(baseline, JSON.stringify(legacy));
  assert.equal(run(["--cat", "secrets", "--baseline", baseline, "--ci"]).status, 0);
  assert.equal(read().summary.held, 0); // ignore legacy held flags
  assert.equal(read().comparison.changes.length, 0);
  writeFileSync(baseline, JSON.stringify(initial.results.filter((r) => r.id !== "sudo-01")));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.unbaselined, ["sudo-01"]);
  writeFileSync(baseline, JSON.stringify(initial.results.map((r) => r.id === "sudo-01" ? { ...r, tool_input: { command: "different attack" } } : r)));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.unbaselined, ["sudo-01"]);
  writeFileSync(baseline, JSON.stringify([...initial.results, { ...initial.results.find((r) => r.id === "sudo-01"), id: "retired" }]));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.removed, ["retired"]);

  const previousArtifacts = readFileSync(resultsFile, "utf8");
  for (const args of [["--ci"], ["--cat", "missing"], ["--cat"], ["--wat"], ["--baseline", resultsFile]])
    assert.equal(run(args).status, 2);
  assert.equal(run([], "normal", join(work, "missing-engine")).status, 2);
  symlinkSync(resultsFile, join(work, "alias.json"));
  assert.equal(run(["--baseline", join(work, "alias.json")]).status, 2);
  const previousReport = readFileSync(join(work, "REPORT.md"), "utf8");
  writeFileSync(join(work, "REPORT.md"), JSON.stringify(initial));
  assert.equal(run(["--baseline", join(work, "REPORT.md")]).status, 2);
  assert.deepEqual(JSON.parse(readFileSync(join(work, "REPORT.md"), "utf8")), initial);
  writeFileSync(join(work, "REPORT.md"), previousReport);
  for (const invalid of [[], null, {}, { schemaVersion: 2, results: initial.results }, [initial.results[0], initial.results[0]], [{ ...initial.results[0], verdict: "ERROR" }]]) {
    writeFileSync(baseline, JSON.stringify(invalid));
    assert.equal(run(ci).status, 2);
  }
  writeFileSync(baseline, "not json");
  assert.equal(run(ci).status, 2);
  assert.equal(readFileSync(resultsFile, "utf8"), previousArtifacts);
  assert.equal(run(["--help"], "normal", join(work, "missing-engine")).status, 0);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /redaction is not verified/);
  console.log("CLI checks passed: scoring, metadata, baseline comparison, CI exits, and engine errors.");
} finally {
  rmSync(work, { recursive: true, force: true });
}
