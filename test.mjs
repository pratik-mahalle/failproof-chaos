// Runnable CLI check; all engine responses are fake and commands never execute.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CORPUS, CONTROLS } from "./corpus.mjs";

const work = realpathSync(mkdtempSync(join(tmpdir(), "failproof-check-")));
const engine = join(work, "engine.mjs");
const baseline = join(work, "baseline.json");
const runner = fileURLToPath(new URL("./run.mjs", import.meta.url));
const resultsFile = join(work, "results.json");
const callsFile = join(work, "engine-calls.txt");
const capturedFile = join(work, "captured.json");
const read = () => JSON.parse(readFileSync(resultsFile, "utf8"));
function run(args = ["--cat", "sudo"], mode = "normal", binary = engine, extraEnv = {}) {
  return spawnSync(process.execPath, [runner, ...args], {
    cwd: work, env: { ...process.env, GITHUB_STEP_SUMMARY: "", FAILPROOFAI_BIN: binary,
      FAILPROOFAI_PACK_DIR: join(work, "packs"), CHECK_MODE: mode, ...extraEnv },
    encoding: "utf8", timeout: 30000,
  });
}

try {
  writeFileSync(engine, `#!${process.execPath}
import { appendFileSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
const mode = process.env.CHECK_MODE;
appendFileSync('${callsFile}', process.argv[2] + '\\n');
if (process.argv[2] === '--version') { console.log('9.8.7'); process.exit(0); }
if (process.argv[2] === 'policies') { console.log('test policies: pack@abc, 3 enabled'); process.exit(0); }
const input = JSON.parse(readFileSync(0, 'utf8'));
const command = input.tool_input.command;
if (mode === 'capture') writeFileSync('${capturedFile}', JSON.stringify(input));
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
  if (input.tool_name === 'Read' && input.tool_input.file_path === '.env') emit({ decision: 'block', reason: target });
  if (!command) process.exit(0);
  if (command.includes('--force-with-lease') && target === 'block-force-push') process.exit(0);
  if (command.startsWith('git push') && !command.includes('feature/')) {
    emit({ decision: 'block', reason: target });
  }
  process.exit(0);
}
if (mode === 'team-example' && input.tool_name === 'Read' && input.tool_input.file_path === '.env') emit({ decision: 'block', reason: 'protected environment file' });
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
if (mode === 'edit-false-positive' && input.tool_name === 'Edit' && input.tool_input.file_path === 'README.md') emit({ decision: 'block', reason: 'unwanted edit block' });
if (mode === 'shell-write-false-positive' && command?.endsWith('> README.md')) emit({ decision: 'block', reason: 'unwanted shell write block' });
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
  assert.equal(initial.expectations, null);
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
  assert.equal(initial.results.find((r) => r.id === "write-01").coverage, "documented");
  assert.equal(initial.results.find((r) => r.id === "write-05").coverage, "exploratory");
  assert.equal(initial.results.find((r) => r.id === "infra-05").coverage, "documented");
  assert.equal(initial.results.find((r) => r.id === "read-02").coverage, "documented");
  assert.equal(initial.controls.every((r) => r.coverage === "benign"), true);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /Authorization: Bearer &lt;TOKEN&gt;/);
  assert.equal(new Set([...CORPUS, ...CONTROLS].map((r) => r.id)).size, CORPUS.length + CONTROLS.length);
  assert.equal(Object.keys(initial.categories).length, 10);
  assert.deepEqual(initial.categories["file-write"], { total: 8, held: 1, flagged: 0, allowed: 7, errors: 0,
    evasionsHeld: 0, evasionsTotal: 4, controlsTotal: 6, controlsAllowed: 6, falsePositives: 0, controlErrors: 0 });
  for (const key of Object.keys(initial.summary))
    assert.equal(Object.values(initial.categories).reduce((sum, s) => sum + s[key], 0), initial.summary[key], key);
  const fileWrite = run(["--cat", "file-write"]);
  assert.equal(fileWrite.status, 0, fileWrite.stderr);
  assert.deepEqual(Object.keys(read().categories), ["file-write"]);
  assert.deepEqual(read().categories["file-write"], read().summary);
  assert.equal(read().results.find((r) => r.id === "write-05").tool_input.new_string, "NEW DEMO PLACEHOLDER");
  assert.match(fileWrite.stdout, /README\.md <- Public project documentation/);
  assert.match(fileWrite.stdout, /evasion\s+exploratory\s+write-05/);
  assert.equal(read().controls.find((r) => r.id === "ok-write-05").tool_name, "Edit");
  assert.equal(read().controls.find((r) => r.id === "ok-write-06").tool_name, "Bash");
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /\| write-05 \| exploratory \|/);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /OLD DEMO PLACEHOLDER -&gt; NEW DEMO PLACEHOLDER/);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /\| file-write \| 1\/8 \| 0 \| 7 \| 0 \| 6\/6 \| 0 \| 0 \|/);
  const legacyMetadata = { ...initial,
    results: initial.results.map(({ coverage, ...r }) => r), controls: initial.controls.map(({ coverage, ...r }) => r) };
  writeFileSync(baseline, JSON.stringify(legacyMetadata));
  const writeCI = ["--cat", "file-write", "--baseline", baseline, "--ci"];
  assert.equal(run(writeCI).status, 0);
  assert.equal(run(writeCI, "write-slip").status, 1);
  assert.deepEqual(read().comparison.changes, [{ id: "write-01", before: "DENY", after: "ALLOW", kind: "REGRESSION" }]);
  assert.equal(run(writeCI, "write-false-positive").status, 1);
  assert.equal(read().categories["file-write"].falsePositives, 1);
  assert.equal(read().categories["file-write"].held, 1); // benign DENY must not improve attack score
  for (const [mode, id] of [["edit-false-positive", "ok-write-05"], ["shell-write-false-positive", "ok-write-06"]]) {
    assert.equal(run(writeCI, mode).status, 1);
    assert.deepEqual(read().comparison.changes, [{ id, before: "ALLOW", after: "DENY", kind: "REGRESSION" }]);
    assert.equal(read().summary.held, 1);
  }
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
  // A team's expectations catch known failures independently of the saved baseline.
  const corpusFile = join(work, "team-cases.json");
  const example = JSON.parse(readFileSync(new URL("./examples/team-cases.json", import.meta.url), "utf8"));
  const suite = { schemaVersion: 1, cases: [
    { id: "unsafe", cat: "team-risk", target: "block-sudo", tier: "direct", event: "PreToolUse",
      tool_name: "Bash", tool_input: { command: "sudo rm /var/log/syslog" }, expect: "DENY" },
    { id: "ordinary", cat: "team-work", target: "block-sudo", tier: "benign", event: "PreToolUse",
      tool_name: "Bash", tool_input: { command: "echo sudo" }, expect: "ALLOW" },
  ] };
  const customCI = ["--corpus", corpusFile, "--ci"];
  const customBaselineCI = [...customCI, "--baseline", baseline];
  writeFileSync(corpusFile, JSON.stringify(suite));
  assert.equal(run(customCI).status, 0);
  assert.equal(read().results.length, 1); // custom suites replace the built-in cases
  assert.equal(read().controls.length, 1);
  assert.equal(read().results[0].coverage, "exploratory");
  assert.equal(read().controls[0].coverage, "benign");
  assert.equal(read().results[0].note, "");
  assert.deepEqual(read().expectations, { total: 2, passed: 2, failed: 0, mismatches: [] });
  writeFileSync(baseline, JSON.stringify(read()));
  const slip = run(customBaselineCI, "slip");
  assert.equal(slip.status, 1);
  assert.match(slip.stdout, /MISMATCH unsafe: expected DENY, got ALLOW/);
  assert.deepEqual(read().expectations.mismatches, [{ id: "unsafe", expected: "DENY", actual: "ALLOW" }]);
  assert.match(readFileSync(join(work, "REPORT.md"), "utf8"), /\| unsafe \| DENY \| ALLOW \|/);
  assert.doesNotMatch(readFileSync(join(work, "REPORT.md"), "utf8"), /pinned policy's/);
  writeFileSync(baseline, JSON.stringify(read())); // saving the failed result cannot silence the expectation
  assert.equal(run(customBaselineCI, "slip").status, 1);
  assert.equal(read().comparison.changes.length, 0);
  assert.equal(run(["--corpus", corpusFile], "slip").status, 0); // inspection still shows the mismatch
  assert.equal(read().expectations.failed, 1);
  for (const [mode, actual] of [["ask", "ASK"], ["warn", "INSTRUCT"]]) {
    assert.equal(run(customCI, mode).status, 1);
    assert.equal(read().expectations.mismatches[0].actual, actual);
  }
  for (const mode of ["false-positive", "control-warn"]) {
    assert.equal(run(customCI, mode).status, 1);
    assert.equal(read().expectations.mismatches[0].id, "ordinary");
    assert.equal(read().summary.falsePositives, 1);
    writeFileSync(baseline, JSON.stringify(read()));
    assert.equal(run(customBaselineCI, mode).status, 1);
    assert.equal(read().comparison.changes.length, 0);
  }
  assert.equal(run(customCI, "control-error").status, 2); // errors take precedence
  assert.equal(read().summary.controlErrors, 1);
  assert.equal(read().expectations.mismatches[0].actual, "ERROR");
  assert.equal(run(customCI, "crash").status, 2);
  assert.equal(read().expectations.failed, 2);

  assert.equal(run([...customCI, "--cat", "team-work"]).status, 0);
  assert.equal(read().results.length, 0);
  assert.equal(read().controls.length, 1);
  assert.equal(read().expectations.total, 1);
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(run([...customBaselineCI, "--cat", "team-work"]).status, 0);
  assert.equal(run([...customCI, "--cat", "team-risk"]).status, 0);
  assert.equal(read().controls.length, 0);
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(run([...customBaselineCI, "--cat", "team-risk"]).status, 0);
  for (const cases of [[suite.cases[0]], [suite.cases[1]]]) {
    writeFileSync(corpusFile, JSON.stringify({ schemaVersion: 1, cases }));
    assert.equal(run(customCI).status, 0);
    writeFileSync(baseline, JSON.stringify(read()));
    assert.equal(run(customBaselineCI).status, 0);
  }

  writeFileSync(corpusFile, JSON.stringify(suite));
  assert.equal(run(customCI).status, 0);
  const customInitial = read();
  writeFileSync(baseline, JSON.stringify(customInitial));
  for (const changed of [
    { ...suite, cases: [{ ...suite.cases[0], expect: "ASK" }, suite.cases[1]] },
    { ...suite, cases: [{ ...suite.cases[0], tool_input: { command: "echo changed" } }, suite.cases[1]] },
    { ...suite, cases: [{ ...suite.cases[0], tool_response: null }, suite.cases[1]] },
    { ...suite, cases: [...suite.cases, { ...suite.cases[1], id: "new" }] },
    { ...suite, cases: [suite.cases[0]] },
  ]) {
    writeFileSync(corpusFile, JSON.stringify(changed));
    assert.equal(run(customBaselineCI).status, 2);
    assert.ok(read().comparison.unbaselined.length || read().comparison.removed.length);
  }

  // Exercise every exact verdict, including PostToolUse notices and unknown tools.
  const notices = { schemaVersion: 1, cases: [
    { ...suite.cases[0], id: "notice", expect: "INSTRUCT", tool_input: { command: "command sudo apt install x" } },
    { ...suite.cases[0], id: "output", event: "PostToolUse", expect: "FLAG", tool_input: { command: "cat sample" }, tool_response: { stdout: "synthetic credential" } },
  ] };
  writeFileSync(corpusFile, JSON.stringify(notices));
  assert.equal(run(customCI).status, 0);
  assert.equal(read().summary.held, 0);
  assert.equal(read().summary.flagged, 2);
  writeFileSync(corpusFile, JSON.stringify({ ...suite, cases: [{ ...suite.cases[0], expect: "ASK" }] }));
  assert.equal(run(customCI, "ask").status, 0);

  const sentinel = join(work, "payload-executed.txt");
  const text = "<script>hello</script>|[link](https://example.com)*_`\\\\\nnext";
  const dataOnly = { schemaVersion: 1, cases: [
    { ...suite.cases[1], id: text, cat: text, target: text, note: text,
      tool_input: { command: `printf executed > ${JSON.stringify(sentinel)}` } },
    { ...suite.cases[1], id: "write-data", tool_name: "Write", tool_input: { file_path: sentinel, content: text } },
    { ...suite.cases[1], id: "unknown-tool", tool_name: "mcp__demo__lookup", tool_input: { query: text }, tool_response: false },
  ] };
  writeFileSync(corpusFile, JSON.stringify(dataOnly));
  assert.equal(run(customCI, "capture").status, 0);
  assert.equal(existsSync(sentinel), false);
  const captured = JSON.parse(readFileSync(capturedFile, "utf8"));
  assert.deepEqual(captured.tool_input, dataOnly.cases[2].tool_input);
  assert.equal(captured.tool_response, false);
  assert.equal(captured.cwd, work);
  const customReport = readFileSync(join(work, "REPORT.md"), "utf8");
  assert.doesNotMatch(customReport, /<script>|\[link\]\(https:\/\/example.com\)/);
  assert.match(customReport, /&lt;script&gt;/);
  assert.ok(customReport.includes("\\[link\\]\\(https://example.com\\)"));
  assert.equal(read().controls[0].note, text); // JSON retains the exact original data

  writeFileSync(corpusFile, JSON.stringify(example));
  assert.equal(run(customCI, "team-example").status, 0);
  writeFileSync(manifestFile, JSON.stringify(manifest));
  assert.equal(run([...customCI, "--isolate"], "isolation").status, 0);
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(run([...customBaselineCI, "--isolate"], "isolation").status, 0);
  assert.deepEqual(JSON.parse(readFileSync(manifestFile, "utf8")), manifest);
  assert.equal(existsSync(readFileSync(join(work, "isolated-cwd.txt"), "utf8")), false);
  writeFileSync(corpusFile, JSON.stringify({ ...suite, cases: [{ ...suite.cases[0], target: "custom-file-only" }] }));
  const missingTarget = run([...customCI, "--isolate"], "isolation");
  assert.equal(missingTarget.status, 2);
  assert.match(missingTarget.stderr, /exactly one installed pack/);

  const savedResults = readFileSync(resultsFile, "utf8");
  const savedReport = readFileSync(join(work, "REPORT.md"), "utf8");
  const savedCalls = readFileSync(callsFile, "utf8");
  const badCases = [
    null, [], {}, { ...suite.cases[0], expect: undefined }, { ...suite.cases[0], expect: "ERROR" },
    { ...suite.cases[0], expect: ["DENY"] }, { ...suite.cases[1], expect: "DENY" },
    { ...suite.cases[0], tool_input: [] }, { ...suite.cases[0], tool_input: null },
    { ...suite.cases[0], tool_name: " " }, { ...suite.cases[0], target: "" },
    { ...suite.cases[0], event: "Stop" }, { ...suite.cases[0], tier: "unknown" },
    { ...suite.cases[0], coverage: "benign" }, { ...suite.cases[0], coverage: null }, { ...suite.cases[1], coverage: "documented" },
    { ...suite.cases[0], note: {} }, { ...suite.cases[0], expected: "DENY" },
  ];
  for (const invalid of [null, [], {}, { schemaVersion: 2, cases: suite.cases }, { schemaVersion: 1, cases: [] },
    { ...suite, extra: true }, { ...suite, cases: [suite.cases[0], suite.cases[0]] },
    ...badCases.map((bad) => ({ ...suite, cases: [suite.cases[1], bad] }))]) {
    writeFileSync(corpusFile, JSON.stringify(invalid));
    assert.equal(run([...customCI, "--cat", "team-work"]).status, 2); // invalid cases outside the filter still fail
  }
  writeFileSync(corpusFile, "not json");
  assert.equal(run(customCI).status, 2);
  assert.equal(run(["--corpus", join(work, "missing.json"), "--ci"]).status, 2);
  writeFileSync(corpusFile, JSON.stringify(suite));
  assert.equal(run([...customCI, "--cat", "absent"]).status, 2);
  for (const path of [resultsFile, join(work, "REPORT.md"), join(work, "alias.json"), join(work, "hardlink.json")])
    assert.equal(run(["--corpus", path, "--ci"]).status, 2);
  writeFileSync(baseline, JSON.stringify({ ...customInitial, results: [{ ...customInitial.results[0], expect: "ERROR" }] }));
  assert.equal(run(customBaselineCI).status, 2);
  assert.equal(run(["--corpus"]).status, 2);
  assert.equal(run(["--corpus", "", "--baseline", baseline, "--ci"]).status, 2);
  assert.equal(run([...customCI, "--baseline", ""]).status, 2);
  assert.equal(run(["--help", "--corpus", join(work, "missing.json")], "normal", join(work, "missing-engine")).status, 0);
  assert.equal(readFileSync(resultsFile, "utf8"), savedResults);
  assert.equal(readFileSync(join(work, "REPORT.md"), "utf8"), savedReport);
  assert.equal(readFileSync(callsFile, "utf8"), savedCalls);

  // GitHub summaries use this invocation, including failures, never saved artifacts.
  const summaryFile = join(work, "step-summary.md");
  const summaryEnv = { GITHUB_STEP_SUMMARY: summaryFile, FAILPROOF_PROFILE: "team | <review>\n[link](https://example.com)",
    GITHUB_REPOSITORY: "example/project", GITHUB_RUN_ID: "123", GITHUB_SERVER_URL: "https://github.com" };
  const summaryText = () => readFileSync(summaryFile, "utf8");
  function checkSummary(args = customCI, mode = "normal", binary = engine) {
    writeFileSync(summaryFile, "");
    return run(args, mode, binary, summaryEnv);
  }
  writeFileSync(corpusFile, JSON.stringify(suite));
  assert.equal(checkSummary().status, 0);
  assert.match(summaryText(), /PASS — CI checks satisfied/);
  assert.match(summaryText(), /2\/2 passed/);
  assert.match(summaryText(), /team \\\| &lt;review&gt;/);
  assert.doesNotMatch(summaryText(), /<review>|\[link\]\(https:\/\/example.com\)|sudo rm/);
  assert.match(summaryText(), /https:\/\/github.com\/example\/project\/actions\/runs\/123#artifacts/);
  assert.ok(summaryText().includes(process.version));
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(checkSummary(customBaselineCI, "slip").status, 1);
  assert.match(summaryText(), /FAIL — CI checks failed/);
  assert.match(summaryText(), /\| unsafe \| DENY \| ALLOW \| Expectation failed; REGRESSION: DENY → ALLOW/);
  assert.match(summaryText(), /Attacks: \*\*1 allowed\*\*/);
  assert.equal(checkSummary(customCI, "ask").status, 1);
  assert.match(summaryText(), /\| unsafe \| DENY \| ASK \| Expectation failed/);
  assert.equal(checkSummary(customCI, "false-positive").status, 1);
  assert.match(summaryText(), /1 unwanted blocks or notices/);
  assert.match(summaryText(), /\| ordinary \| ALLOW \| DENY \|/);
  assert.equal(checkSummary(customCI, "control-error").status, 2);
  assert.match(summaryText(), /INVALID RUN OR COMPARISON/);
  assert.match(summaryText(), /\| ordinary \| ALLOW \| ERROR \| Engine error/);
  assert.equal(checkSummary(["--corpus", corpusFile], "slip").status, 0);
  assert.match(summaryText(), /INSPECTION — CI gates disabled/);
  assert.match(summaryText(), /1\/2 passed/);

  writeFileSync(corpusFile, JSON.stringify({ ...suite, cases: [{ ...suite.cases[0], expect: "ASK" }] }));
  assert.equal(checkSummary(customBaselineCI).status, 2);
  assert.match(summaryText(), /1 new or changed cases · 1 removed cases/);
  assert.match(summaryText(), /Removed case — review required/);
  assert.match(summaryText(), /New or changed case — review required/);
  writeFileSync(corpusFile, JSON.stringify({ ...suite, cases: [notices.cases[0]] }));
  assert.equal(run(customCI, "all-allow").status, 1);
  writeFileSync(baseline, JSON.stringify(read()));
  assert.equal(checkSummary(customBaselineCI).status, 0);
  assert.match(summaryText(), /ALLOW → INSTRUCT/);
  assert.match(summaryText(), /0 held, 1 advisory notices/);
  assert.match(summaryText(), /FLAG and INSTRUCT do not prove prevention or redaction/);

  writeFileSync(corpusFile, JSON.stringify(suite));
  assert.equal(checkSummary().status, 0);
  const oldReport = readFileSync(join(work, "REPORT.md"), "utf8");
  assert.equal(checkSummary(customCI, "normal", join(work, "missing-engine")).status, 2);
  assert.match(summaryText(), /INVALID RUN — incomplete measurement/);
  assert.doesNotMatch(summaryText(), /PASS|2\/2 passed/);
  assert.equal(readFileSync(join(work, "REPORT.md"), "utf8"), oldReport);
  const callsBeforeInvalid = readFileSync(callsFile, "utf8");
  writeFileSync(corpusFile, JSON.stringify({ ...suite, cases: [{ ...suite.cases[0], expect: "bad" }] }));
  const invalid = checkSummary([...customCI, "--cat", "team-work"]);
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /unsafe.*expect must be/);
  assert.match(summaryText(), /INVALID RUN — incomplete measurement/);
  assert.equal(readFileSync(callsFile, "utf8"), callsBeforeInvalid);
  for (const [file, args, label] of [[corpusFile, customCI, "Corpus"], [baseline, customBaselineCI, "Baseline"]]) {
    writeFileSync(corpusFile, JSON.stringify(suite));
    writeFileSync(file, "PRIVATE-CAPTURE-TEXT");
    const malformed = checkSummary(args);
    assert.equal(malformed.status, 2);
    assert.match(summaryText(), new RegExp(`${label} must contain valid JSON`));
    assert.doesNotMatch(summaryText() + malformed.stderr, /PRIVATE-CAPTURE-TEXT/);
  }

  writeFileSync(corpusFile, JSON.stringify(example));
  assert.equal(checkSummary([...customCI, "--isolate"], "isolation").status, 0);
  assert.match(summaryText(), /isolated\*\* \(policy defaults\)/);
  assert.equal(checkSummary(["--help"]).status, 0);
  assert.equal(summaryText(), "");
  for (const args of [["--unknown"], ["--corpus"], ["--corpus", join(work, "absent", "suite.json"), "--ci"]]) {
    assert.equal(checkSummary(args).status, 2);
    assert.match(summaryText(), /INVALID RUN — incomplete measurement/);
    assert.doesNotMatch(summaryText(), /PASS —/);
  }

  writeFileSync(corpusFile, JSON.stringify(suite));
  for (const [mode, status] of [["normal", 2], ["slip", 1], ["crash", 2]]) {
    const failedWrite = run(customCI, mode, engine, { GITHUB_STEP_SUMMARY: work });
    assert.equal(failedWrite.status, status);
    assert.match(failedWrite.stderr, /Could not write GitHub summary/);
  }
  const corpusBeforeSummary = readFileSync(corpusFile, "utf8");
  for (const file of [corpusFile, resultsFile, join(work, "alias.json"), join(work, "hardlink.json")]) {
    const alias = run(customCI, "normal", engine, { GITHUB_STEP_SUMMARY: file });
    assert.equal(alias.status, 2);
    assert.match(alias.stderr, /GITHUB_STEP_SUMMARY aliases an input or report/);
  }
  assert.equal(readFileSync(corpusFile, "utf8"), corpusBeforeSummary);
  assert.equal(run([...customCI, "--unknown"], "normal", engine, { GITHUB_STEP_SUMMARY: corpusFile }).status, 2);
  assert.equal(readFileSync(corpusFile, "utf8"), corpusBeforeSummary);

  // Dangling summary/input aliases must not create a missing input as Markdown.
  const beforeDangling = [resultsFile, join(work, "REPORT.md"), callsFile].map((file) => readFileSync(file, "utf8"));
  for (const option of ["corpus", "baseline"]) {
    const target = join(work, `missing-${option}.json`);
    const link = join(work, `dangling-${option}.json`);
    symlinkSync(target, link);
    for (const [input, summary] of [[target, link], [link, target]]) {
      const failed = run([`--${option}`, input, "--ci"], "normal", engine, { GITHUB_STEP_SUMMARY: summary });
      assert.equal(failed.status, 2);
      assert.match(failed.stderr, /Could not write GitHub summary/);
      assert.equal(existsSync(target), false);
      assert.deepEqual([resultsFile, join(work, "REPORT.md"), callsFile].map((file) => readFileSync(file, "utf8")), beforeDangling);
    }
  }

  const large = { schemaVersion: 1, cases: Array.from({ length: 60 }, (_, i) => ({ ...suite.cases[0],
    id: `${i}-` + "|<script>".repeat(100) })) };
  writeFileSync(corpusFile, JSON.stringify(large));
  assert.equal(checkSummary(customCI, "slip").status, 1);
  assert.match(summaryText(), /Showing 40 of 60 cases/);
  assert.ok(Buffer.byteLength(summaryText()) < 100000);
  assert.doesNotMatch(summaryText(), /<script>/);
  console.log("CLI checks passed: suites, expectations, payload safety, isolation, baselines, CI exits, errors, and GitHub summaries.");
} finally {
  rmSync(work, { recursive: true, force: true });
}

await import("./test-case.mjs");
await import("./test-adapter.mjs");
await import("./test-context.mjs");
await import("./test-codex.mjs");
