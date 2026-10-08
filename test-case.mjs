// Case-authoring checks; imported commands and writes remain data throughout.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, linkSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateCorpus } from "./suite.mjs";

const work = realpathSync(mkdtempSync(join(tmpdir(), "failproof-case-check-")));
const helper = fileURLToPath(new URL("./case.mjs", import.meta.url));
const runner = fileURLToPath(new URL("./run.mjs", import.meta.url));
const inputFile = join(work, "payload.json");
const outputFile = join(work, "draft.json");
const engine = join(work, "engine.mjs");
const calls = join(work, "calls.jsonl");
const sentinel = join(work, "payload-executed");
const results = join(work, "results.json");
const report = join(work, "REPORT.md");
const read = (path) => JSON.parse(readFileSync(path, "utf8"));
const payload = { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: ".env" } };
const options = { input: inputFile, id: "env-read", cat: "project-files", target: "block-env-files", tier: "direct", expect: "DENY", out: outputFile };
const args = (values) => Object.entries(values).flatMap(([key, value]) => value === undefined ? [] : [`--${key}`, value]);
function draft(overrides = {}, extra = []) {
  return spawnSync(process.execPath, [helper, ...args({ ...options, ...overrides }), ...extra], {
    cwd: work, env: { ...process.env, FAILPROOFAI_BIN: engine }, encoding: "utf8", timeout: 10000,
  });
}
function run(corpus, mode = "fixed", extra = []) {
  return spawnSync(process.execPath, [runner, "--corpus", corpus, "--ci", ...extra], {
    cwd: work, env: { ...process.env, GITHUB_STEP_SUMMARY: "", FAILPROOFAI_BIN: engine, CASE_CHECK_MODE: mode }, encoding: "utf8", timeout: 10000,
  });
}

try {
  writeFileSync(engine, `#!${process.execPath}
import { appendFileSync, readFileSync } from 'node:fs';
const calls = ${JSON.stringify(calls)};
if (process.argv[2] === '--version') { appendFileSync(calls, 'version\\n'); console.log('case-test'); process.exit(0); }
if (process.argv[2] === 'policies') { appendFileSync(calls, 'policies\\n'); console.log('synthetic guards'); process.exit(0); }
const payload = JSON.parse(readFileSync(0, 'utf8'));
appendFileSync(calls, JSON.stringify(payload) + '\\n');
const mode = process.env.CASE_CHECK_MODE;
const command = payload.tool_input.command;
const deny = (payload.tool_input.file_path === '.env' && mode !== 'unsafe') || command === 'rm -rf /' ||
  (command === "echo 'rm -rf /'" && mode === 'unwanted');
if (deny) console.log(JSON.stringify({ decision: 'block', reason: 'synthetic guard' }));
`, { mode: 0o755 });
  writeFileSync(inputFile, JSON.stringify(payload));
  writeFileSync(results, "existing results");
  writeFileSync(report, "existing report");
  const created = draft({ coverage: "documented", note: "Synthetic protected-file case." });
  assert.equal(created.status, 0, created.stderr);
  const suite = read(outputFile);
  assert.deepEqual(suite, { schemaVersion: 1, cases: [{
    id: "env-read", cat: "project-files", target: "block-env-files", tier: "direct",
    event: "PreToolUse", tool_name: "Read", tool_input: { file_path: ".env" }, expect: "DENY",
    coverage: "documented", note: "Synthetic protected-file case.",
  }] });
  assert.equal(existsSync(calls), false); // Drafting never calls the engine, including preflight.
  assert.match(created.stderr, /Review\/redact/);
  assert.match(created.stderr, /runner's cwd.*does not restore session state/);
  assert.match(created.stderr, /ordinary ALLOW counterpart/);
  assert.equal(readFileSync(results, "utf8"), "existing results");
  assert.equal(readFileSync(report, "utf8"), "existing report");

  const original = readFileSync(inputFile, "utf8");
  const existing = readFileSync(outputFile, "utf8");
  symlinkSync(inputFile, join(work, "input-symlink.json"));
  linkSync(inputFile, join(work, "input-hardlink.json"));
  symlinkSync(join(work, "missing-target.json"), join(work, "dangling.json"));
  for (const out of [inputFile, outputFile, results, report, join(work, "input-symlink.json"), join(work, "input-hardlink.json"), join(work, "dangling.json")]) {
    const result = draft({ out });
    assert.equal(result.status, 2, out);
    assert.match(result.stderr, /EEXIST/);
  }
  assert.equal(readFileSync(inputFile, "utf8"), original);
  assert.equal(readFileSync(outputFile, "utf8"), existing);
  assert.equal(existsSync(join(work, "missing-target.json")), false);

  const invalidOut = join(work, "invalid.json");
  for (const key of Object.keys(options)) {
    assert.equal(draft({ [key]: undefined, out: key === "out" ? undefined : invalidOut }).status, 2, key);
    assert.equal(draft({ [key]: " ", out: key === "out" ? " " : invalidOut }).status, 2, key);
  }
  for (const [overrides, expected] of [
    [{ tier: "unknown" }, /tier must/], [{ expect: "ERROR" }, /expect must/],
    [{ tier: "benign", expect: "DENY" }, /ALLOW for tier benign/],
    [{ coverage: "benign" }, /coverage must/], [{ input: join(work, "missing") }, /ENOENT/],
  ]) {
    const result = draft({ ...overrides, out: invalidOut });
    assert.equal(result.status, 2);
    assert.match(result.stderr, expected);
  }
  assert.equal(draft({ out: invalidOut }, ["--unknown"]).status, 2);
  assert.equal(draft({ out: invalidOut }, ["unexpected-positional"]).status, 2);
  for (const bad of [null, [], {}, { ...payload, tool_input: null }, { ...payload, tool_input: [] },
    { ...payload, tool_name: "" }, { ...payload, hook_event_name: "Stop" }, { ...payload, decision: "ALLOW" }]) {
    writeFileSync(inputFile, JSON.stringify(bad));
    assert.equal(draft({ out: invalidOut }).status, 2);
  }
  writeFileSync(inputFile, "not JSON containing PRIVATE-CAPTURE-TEXT");
  const invalidJSON = draft({ out: invalidOut });
  assert.equal(invalidJSON.status, 2);
  assert.match(invalidJSON.stderr, /valid JSON/);
  assert.doesNotMatch(invalidJSON.stderr, /PRIVATE-CAPTURE-TEXT/);
  assert.equal(existsSync(invalidOut), false);
  assert.equal(existsSync(calls), false);
  assert.equal(readFileSync(results, "utf8"), "existing results");
  assert.equal(readFileSync(report, "utf8"), "existing report");
  assert.equal(draft({}, ["--help"]).status, 0);

  for (const [index, response] of [undefined, false, null, { stdout: "sample", nested: [false, null, { value: 1 }] }].entries()) {
    const captured = { hook_event_name: "PostToolUse", tool_name: "mcp__example__lookup",
      tool_input: { command: `touch ${sentinel}`, nested: { array: [false, null, "text"] } },
      ...(response !== undefined ? { tool_response: response } : {}),
      cwd: "PRIVATE-CAPTURE-CWD", session_id: "PRIVATE-CAPTURE-SESSION", transcript_path: "PRIVATE-CAPTURE-PATH",
      permission_mode: "PRIVATE-CAPTURE-MODE", tool_use_id: "PRIVATE-CAPTURE-ID" };
    writeFileSync(inputFile, JSON.stringify(captured));
    const path = join(work, `roundtrip-${index}.json`);
    const result = draft({ id: `roundtrip-${index}`, tier: "benign", expect: "ALLOW", out: path });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /Omitted capture metadata: cwd, session_id, transcript_path, permission_mode, tool_use_id/);
    assert.doesNotMatch(result.stderr + result.stdout + readFileSync(path, "utf8"), /PRIVATE-CAPTURE-/);
    const c = read(path).cases[0];
    assert.equal(c.coverage, "benign");
    assert.equal(c.note, "");
    assert.deepEqual(c.tool_input, captured.tool_input);
    assert.equal(Object.hasOwn(c, "tool_response"), response !== undefined);
    assert.deepEqual(c.tool_response, response);
    assert.equal(run(path).status, 0);
    const replayed = JSON.parse(readFileSync(calls, "utf8").trim().split("\n").at(-1));
    assert.deepEqual(replayed.tool_input, captured.tool_input);
    assert.equal(Object.hasOwn(replayed, "tool_response"), response !== undefined);
    assert.deepEqual(replayed.tool_response, response);
    assert.equal(replayed.cwd, work);
    assert.equal(replayed.session_id, "chaos");
    assert.equal(existsSync(sentinel), false);
  }

  // A generated pair exposes an unsafe allowance, and fixing it preserves ordinary work.
  const publicPath = join(work, "public.json");
  const publicInput = fileURLToPath(new URL("./examples/hook-public-read.json", import.meta.url));
  assert.equal(draft({ input: publicInput, id: "public-read", tier: "benign", expect: "ALLOW", out: publicPath }).status, 0);
  const pairFile = join(work, "pair.json");
  writeFileSync(pairFile, JSON.stringify({ schemaVersion: 1, cases: [...suite.cases, ...read(publicPath).cases] }));
  assert.equal(run(pairFile, "unsafe").status, 1);
  assert.equal(read(results).summary.controlsAllowed, 1);
  assert.deepEqual(read(results).expectations.mismatches, [{ id: "env-read", expected: "DENY", actual: "ALLOW" }]);
  const failedBaseline = join(work, "failed-baseline.json");
  writeFileSync(failedBaseline, readFileSync(results));
  assert.equal(run(pairFile, "unsafe", ["--baseline", failedBaseline]).status, 1);
  assert.equal(run(pairFile, "fixed", ["--baseline", failedBaseline]).status, 0);
  assert.equal(read(results).expectations.passed, 2);

  // Synthetic unwanted-block fix: allow quoted text while keeping actual deletion denied.
  const quoteCases = [];
  for (const [id, command, tier, expect] of [["quoted", "echo 'rm -rf /'", "benign", "ALLOW"], ["deletion", "rm -rf /", "direct", "DENY"]]) {
    writeFileSync(inputFile, JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
    const out = join(work, `${id}.json`);
    assert.equal(draft({ id, target: "block-rm-rf", tier, expect, out }).status, 0);
    quoteCases.push(...read(out).cases);
  }
  writeFileSync(pairFile, JSON.stringify({ schemaVersion: 1, cases: quoteCases }));
  assert.equal(run(pairFile, "unwanted").status, 1);
  assert.equal(read(results).summary.falsePositives, 1);
  writeFileSync(failedBaseline, readFileSync(results));
  assert.equal(run(pairFile, "unwanted", ["--baseline", failedBaseline]).status, 1);
  assert.equal(run(pairFile, "fixed", ["--baseline", failedBaseline]).status, 0);
  assert.equal(read(results).summary.held, 1);
  assert.equal(read(results).summary.controlsAllowed, 1);

  writeFileSync(inputFile, JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: sentinel, content: "must not write" } }));
  const writeDraft = join(work, "write.json");
  assert.equal(draft({ tier: "benign", expect: "ALLOW", out: writeDraft }).status, 0);
  assert.equal(run(writeDraft).status, 0);
  assert.equal(existsSync(sentinel), false);

  assert.throws(() => validateCorpus({ ...suite, cases: [...suite.cases, ...suite.cases] }), /env-read.*id must be unique/);
  for (const [field, value, message] of [["cat", "", /cat must be a nonempty string/], ["note", null, /note must be a string/],
    ["coverage", null, /coverage must/], ["expect", ["DENY"], /expect must/], ["surprise", true, /field surprise is unsupported/]]) {
    assert.throws(() => validateCorpus({ schemaVersion: 1, cases: [{ ...suite.cases[0], [field]: value }] }), (error) => {
      assert.match(error.message, /case "env-read" at index 0/);
      assert.match(error.message, message);
      return true;
    });
  }
  console.log("Case drafting checks passed: validation, exclusive writes, metadata omission, response fidelity, payload safety, and paired regressions.");
} finally {
  rmSync(work, { recursive: true, force: true });
}
