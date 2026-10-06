// Runnable CLI check; all engine responses are fake and commands never execute.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CORPUS, CONTROLS } from "./corpus.mjs";

const work = mkdtempSync(join(tmpdir(), "failproof-check-"));
const engine = join(work, "engine.mjs");
const baseline = join(work, "baseline.json");
const runner = fileURLToPath(new URL("./run.mjs", import.meta.url));
const resultsFile = join(work, "results.json");
const read = () => JSON.parse(readFileSync(resultsFile, "utf8"));
function run(args = ["--cat", "sudo"], mode = "normal", binary = engine) {
  return spawnSync(process.execPath, [runner, ...args], {
    cwd: work, env: { ...process.env, FAILPROOFAI_BIN: binary, FAILPROOFAI_PACK_DIR: join(work, "packs"), CHECK_MODE: mode },
    encoding: "utf8", timeout: 30000,
  });
}

try {
  writeFileSync(engine, `#!${process.execPath}
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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
if (mode === 'isolation') {
  const manifest = JSON.parse(readFileSync(process.env.FAILPROOFAI_PACK_DIR + '/installed.json', 'utf8'));
  if (manifest.packs.length !== 1 || manifest.packs[0].enabled.length !== 1 || input.cwd !== process.cwd() || !existsSync(input.cwd + '/.failproofai')) process.exit(1);
  writeFileSync('${join(work, "isolated-cwd.txt")}', input.cwd);
  const target = manifest.packs[0].enabled[0];
  if (command.includes('--force-with-lease') && target === 'block-force-push') process.exit(0);
  if (command.startsWith('git push') && !command.includes('feature/')) {
    emit({ decision: 'block', reason: target });
  }
  process.exit(0);
}
if (command === 'echo sudo') {
  if (mode === 'false-positive') emit({ decision: 'block', reason: 'false positive' });
  if (mode === 'control-warn') emit({ hookSpecificOutput: { additionalContext: 'false notice' } });
  if (mode === 'control-error') process.exit(1);
}
if (input.hook_event_name === 'PostToolUse' && !/^(Build completed|HTTP status|Example|Authorization: Bearer <TOKEN>)/.test(input.tool_response.stdout)) emit({ hookSpecificOutput: { additionalContext: 'secret detected' } });
if (input.tool_name === 'Write' && input.tool_input.file_path === 'secrets/service.pem') {
  if (mode === 'write-slip') process.exit(0);
  emit({ decision: 'block', reason: 'protected filename' });
}
if (mode === 'write-false-positive' && input.tool_input.file_path === 'docs/credentials-guide.md') emit({ decision: 'block', reason: 'unwanted documentation block' });
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
  assert.equal(initial.schemaVersion, 1);
  assert.equal(initial.mode, "combined");
  assert.equal(initial.controls.length, CONTROLS.length);
  assert.equal(initial.summary.controlsAllowed, CONTROLS.length);
  assert.equal(initial.summary.falsePositives, 0);
  assert.equal(initial.summary.controlErrors, 0);
  assert.equal(initial.engine.version, "9.8.7");
  assert.match(initial.policies, /pack@abc/);
  assert.equal(initial.summary.held, 2);
  assert.equal(initial.summary.flagged, 6);
  assert.equal(initial.summary.allowed, CORPUS.length - 8);
  assert.equal(initial.results.find((r) => r.id === "sec-01").verdict, "FLAG");
  assert.equal(initial.results.find((r) => r.id === "sec-01").held, false);
  assert.equal(initial.results.find((r) => r.id === "pkg-01").held, false);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /Authorization: Bearer &lt;TOKEN&gt;/);
  assert.equal(new Set([...CORPUS, ...CONTROLS].map((r) => r.id)).size, CORPUS.length + CONTROLS.length);
  assert.equal(Object.keys(initial.categories).length, 10);
  assert.deepEqual(initial.categories["file-write"], { total: 8, held: 1, flagged: 0, allowed: 7, errors: 0,
    evasionsHeld: 0, evasionsTotal: 4, controlsTotal: 4, controlsAllowed: 4, falsePositives: 0, controlErrors: 0 });
  for (const key of Object.keys(initial.summary))
    assert.equal(Object.values(initial.categories).reduce((sum, s) => sum + s[key], 0), initial.summary[key], key);
  const fileWrite = run(["--cat", "file-write"]);
  assert.equal(fileWrite.status, 0, fileWrite.stderr);
  assert.deepEqual(Object.keys(read().categories), ["file-write"]);
  assert.deepEqual(read().categories["file-write"], read().summary);
  assert.equal(read().results.find((r) => r.id === "write-05").tool_input.new_string, "NEW DEMO PLACEHOLDER");
  assert.match(fileWrite.stdout, /README\.md <- Public project documentation/);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /OLD DEMO PLACEHOLDER -&gt; NEW DEMO PLACEHOLDER/);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /\| file-write \| 1\/8 \| 0 \| 7 \| 0 \| 4\/4 \| 0 \| 0 \|/);
  writeFileSync(baseline, JSON.stringify(initial));
  const writeCI = ["--cat", "file-write", "--baseline", baseline, "--ci"];
  assert.equal(run(writeCI).status, 0);
  assert.equal(run(writeCI, "write-slip").status, 1);
  assert.deepEqual(read().comparison.changes, [{ id: "write-01", before: "DENY", after: "ALLOW", kind: "REGRESSION" }]);
  assert.equal(run(writeCI, "write-false-positive").status, 1);
  assert.equal(read().categories["file-write"].falsePositives, 1);
  assert.equal(read().categories["file-write"].held, 1); // benign DENY must not improve attack score
  const ci = ["--cat", "sudo", "--baseline", baseline, "--ci"];
  assert.equal(run(ci).status, 0); // known ALLOW and warning do not fail CI
  assert.deepEqual(read().summary, { total: 3, held: 1, flagged: 1, allowed: 1, errors: 0, evasionsHeld: 0, evasionsTotal: 2,
    controlsTotal: 3, controlsAllowed: 3, falsePositives: 0, controlErrors: 0 });
  assert.deepEqual(read().categories, { sudo: read().summary });
  assert.equal(run(ci, "slip").status, 1);
  assert.deepEqual(read().comparison.changes, [{ id: "sudo-01", before: "DENY", after: "ALLOW", kind: "REGRESSION" }]);
  assert.equal(run(ci, "warn").status, 1); // block -> warning is a regression
  assert.equal(run(ci, "all-allow").status, 1); // warning -> allow also regresses
  assert.equal(read().comparison.changes.length, 2);
  assert.equal(run(ci, "ask").status, 0);
  assert.equal(run(ci, "all-deny").status, 1); // improved attacks, newly blocked controls
  assert.equal(read().comparison.changes.filter((r) => r.kind === "IMPROVEMENT").length, 2);
  assert.equal(read().comparison.changes.filter((r) => r.kind === "REGRESSION").length, 3);
  for (const mode of ["false-positive", "control-warn"]) {
    assert.equal(run(ci, mode).status, 1);
    assert.equal(read().summary.falsePositives, 1);
    assert.equal(read().categories.sudo.falsePositives, 1);
    assert.equal(read().comparison.changes[0].id, "ok-sudo-01");
  }
  assert.equal(run(ci, "control-error").status, 2);
  assert.equal(read().summary.errors, 0);
  assert.equal(read().summary.controlErrors, 1);
  assert.equal(read().summary.falsePositives, 0);
  assert.equal(read().categories.sudo.controlErrors, 1);
  assert.equal(read().categories.sudo.falsePositives, 0);
  run([], "false-positive");
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(run(ci, "false-positive").status, 0); // reviewed known false positive
  assert.equal(run(ci).status, 0);
  assert.equal(read().comparison.changes[0].kind, "IMPROVEMENT");
  writeFileSync(baseline, JSON.stringify(initial));
  assert.equal(run(ci.slice(0, -1), "slip").status, 0); // comparison without gating
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /<<'PAYLOAD'/);
  assert.deepEqual(JSON.parse(readFileSync(baseline, "utf8")), initial);

  for (const mode of ["crash", "signal", "bad-json", "null", "empty-object", "bad-context", "unknown", "fail-closed", "pack-failure"]) {
    assert.equal(run(ci, mode).status, 2, mode);
    assert.equal(read().summary.errors, 3, mode);
    assert.equal(read().summary.allowed, 0, mode);
    assert.equal(read().summary.controlErrors, 3, mode);
    assert.equal(read().categories.sudo.errors, 3, mode);
    assert.equal(read().categories.sudo.falsePositives, 0, mode);
    assert.equal(read().comparison.changes.length, 0, mode);
  }
  assert.equal(run(ci, "exit2").status, 1);
  assert.equal(read().summary.held, 3);

  const legacy = initial.results.map((r) => ({ ...r, verdict: r.verdict === "FLAG" ? "SANITIZE" : r.verdict, held: true }));
  writeFileSync(baseline, JSON.stringify(legacy));
  assert.equal(run(["--cat", "secrets", "--baseline", baseline, "--ci"]).status, 2); // controls need review
  assert.equal(read().summary.held, 0); // ignore legacy held flags
  assert.equal(read().comparison.changes.length, 0);
  assert.deepEqual(read().comparison.unbaselined, ["ok-sec-01", "ok-sec-02", "ok-sec-03", "ok-sec-04", "ok-sec-05"]);
  assert.equal(run(["--cat", "secrets", "--baseline", baseline]).status, 0);
  writeFileSync(baseline, JSON.stringify({ ...initial, results: initial.results.filter((r) => r.id !== "sudo-01") }));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.unbaselined, ["sudo-01"]);
  writeFileSync(baseline, JSON.stringify({ ...initial, results: initial.results.map((r) => r.id === "sudo-01" ? { ...r, tool_input: { command: "different attack" } } : r) }));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.unbaselined, ["sudo-01"]);
  writeFileSync(baseline, JSON.stringify({ ...initial, results: [...initial.results, { ...initial.results.find((r) => r.id === "sudo-01"), id: "retired" }] }));
  assert.equal(run(ci).status, 2);
  assert.deepEqual(read().comparison.removed, ["retired"]);

  // The native pack manifest selects one target without touching source settings.
  const packsDir = join(work, "packs");
  mkdirSync(join(packsDir, "artifacts"), { recursive: true });
  const artifact = "export default [];";
  writeFileSync(join(packsDir, "artifacts", "pack.mjs"), artifact);
  const manifest = { schemaVersion: 1, packs: [{ id: "test/policies", version: "abc", entry: "artifacts/pack.mjs",
    sha256: createHash("sha256").update(artifact).digest("hex"),
    policies: [...new Set(CORPUS.map((c) => c.target))].map((name) => ({ name })), enabled: [] }] };
  const manifestFile = join(packsDir, "installed.json");
  writeFileSync(manifestFile, JSON.stringify(manifest));
  const isolatedArgs = ["--cat", "git", "--isolate"];
  assert.equal(run(isolatedArgs, "isolation", "./engine.mjs").status, 0);
  const isolated = read();
  assert.equal(isolated.mode, "isolated");
  assert.equal(isolated.summary.held, 5);
  assert.equal(isolated.results.find((r) => r.id === "git-02").reason, "block-force-push");
  assert.equal(isolated.results.find((r) => r.id === "git-04").reason, "block-push-master");
  assert.equal(isolated.controls.find((r) => r.id === "ok-git-03").verdict, "ALLOW");
  assert.equal(isolated.isolation.packs[0].sha256, manifest.packs[0].sha256);
  assert.equal(existsSync(readFileSync(join(work, "isolated-cwd.txt"), "utf8")), false);
  assert.deepEqual(JSON.parse(readFileSync(manifestFile, "utf8")), manifest);
  writeFileSync(baseline, JSON.stringify(isolated));
  assert.equal(run([...isolatedArgs, "--baseline", baseline, "--ci"], "isolation").status, 0);
  assert.equal(run(["--cat", "git", "--baseline", baseline, "--ci"]).status, 2);
  writeFileSync(baseline, JSON.stringify(initial));
  assert.equal(run([...isolatedArgs, "--baseline", baseline, "--ci"], "isolation").status, 2);
  for (const packs of [[], [...manifest.packs, ...manifest.packs], [{ ...manifest.packs[0], sha256: "0".repeat(64) }],
    [{ ...manifest.packs[0], entry: "../../engine.mjs" }]]) {
    writeFileSync(manifestFile, JSON.stringify({ ...manifest, packs }));
    assert.equal(run(isolatedArgs, "isolation").status, 2);
  }

  const previousArtifacts = readFileSync(resultsFile, "utf8");
  for (const args of [["--ci"], ["--cat", "missing"], ["--cat"], ["--wat"], ["--baseline", resultsFile]])
    assert.equal(run(args).status, 2);
  assert.equal(run([], "normal", join(work, "missing-engine")).status, 2);
  symlinkSync(resultsFile, join(work, "alias.json"));
  assert.equal(run(["--baseline", join(work, "alias.json")]).status, 2);
  linkSync(resultsFile, join(work, "hardlink.json"));
  assert.equal(run(["--baseline", join(work, "hardlink.json")]).status, 2);
  const previousReport = readFileSync(join(work, "REPORT.md"), "utf8");
  writeFileSync(join(work, "REPORT.md"), JSON.stringify(initial));
  assert.equal(run(["--baseline", join(work, "REPORT.md")]).status, 2);
  assert.deepEqual(JSON.parse(readFileSync(join(work, "REPORT.md"), "utf8")), initial);
  writeFileSync(join(work, "REPORT.md"), previousReport);
  for (const invalid of [[], null, {}, { schemaVersion: 2, results: initial.results }, [initial.results[0], initial.results[0]], [{ ...initial.results[0], verdict: "ERROR" }],
    { ...initial, mode: "unknown" }, { ...initial, controls: {} }, { ...initial, controls: initial.results },
    { ...initial, controls: [initial.controls[0], initial.controls[0]] }]) {
    writeFileSync(baseline, JSON.stringify(invalid));
    assert.equal(run(ci).status, 2);
  }
  writeFileSync(baseline, "not json");
  assert.equal(run(ci).status, 2);
  assert.equal(readFileSync(resultsFile, "utf8"), previousArtifacts);
  assert.equal(run(["--help"], "normal", join(work, "missing-engine")).status, 0);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /redaction is not verified/);
  console.log("CLI checks passed: category scores, file-write payloads, controls, isolation, baselines, CI exits, and errors.");
} finally {
  rmSync(work, { recursive: true, force: true });
}
