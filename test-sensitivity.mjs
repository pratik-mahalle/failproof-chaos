// Offline checks for copied configuration, result attribution, and failure preservation.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = realpathSync(mkdtempSync(join(tmpdir(), "failproof-sensitivity-test-")));
const cli = fileURLToPath(new URL("./sensitivity.mjs", import.meta.url));
const home = join(root, "source-home"), project = join(root, "project"), cwd = join(project, "nested");
const packs = join(home, "policies", "packs"), manifestFile = join(packs, "installed.json"), artifact = join(packs, "guard.mjs");
const suite = join(root, "cases.json"), calls = join(root, "calls.jsonl"), engine = join(root, "engine.mjs");
const userConfig = join(home, "policies-config.json");
const configBytes = JSON.stringify({ policyParams: { "pack/FailproofAI/policies/block-read-outside-cwd": { allowPaths: ["sample-private-config-value"] } } });
const targets = ["block-env-files", "block-sudo", "block-read-outside-cwd"];
const bytes = "// Offline engine fixture: never imported.\n";
const manifest = { schemaVersion: 1, packs: [{ id: "FailproofAI/policies", version: "fixture1", entry: "guard.mjs",
  sha256: createHash("sha256").update(bytes).digest("hex"), policies: targets.map((name) => ({ name })) }] };
const probe = (id, target, tool_input, tier = "direct", expect = "DENY") =>
  ({ id, cat: "sensitivity", target, tier, event: "PreToolUse", tool_name: tool_input.command ? "Bash" : "Read", tool_input, expect });
const unsafe = probe("env-read", targets[0], { file_path: ".env" });
const benign = probe("ordinary-read", targets[0], { file_path: "public.json" }, "benign", "ALLOW");
const writeJSON = (file, data) => writeFileSync(file, JSON.stringify(data));
const entries = () => existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
let runNumber = 0;
function run({ cases = [unsafe, benign], selected = [targets[0]], mode = "normal", out, env = {}, extra = [] } = {}) {
  writeJSON(suite, { schemaVersion: 1, cases });
  const output = out ?? join(root, `report-${runNumber++}.json`);
  const processEnv = { ...process.env };
  for (const name of Object.keys(processEnv)) if (name.startsWith("FAILPROOFAI_")) delete processEnv[name];
  const result = spawnSync(process.execPath, [cli, "--corpus", suite, "--out", output,
    ...selected.flatMap((target) => ["--target", target]), ...extra], {
    cwd, env: { ...processEnv, FAILPROOFAI_BIN: engine, FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: packs,
      CLAUDE_PROJECT_DIR: cwd, SENSITIVITY_TEST_MODE: mode, ...env }, encoding: "utf8", timeout: 30000,
  });
  assert.ifError(result.error);
  for (const entry of entries()) if (entry.home !== home) assert.equal(existsSync(entry.home), false, "Temporary homes must be removed");
  return { ...result, output, report: existsSync(output) && output !== suite ? JSON.parse(readFileSync(output, "utf8")) : null };
}

try {
  mkdirSync(packs, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  mkdirSync(join(project, ".failproofai"));
  writeFileSync(artifact, bytes);
  writeJSON(manifestFile, manifest);
  writeFileSync(userConfig, configBytes);
  writeFileSync(join(home, "VERSION"), "source version sentinel");
  writeFileSync(join(cwd, "baseline.json"), "baseline sentinel");
  writeFileSync(join(cwd, "results.json"), "results sentinel");
  writeFileSync(join(cwd, "REPORT.md"), "report sentinel");
  writeFileSync(engine, `#!${process.execPath}
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const home = process.env.FAILPROOFAI_HOME, calls = ${JSON.stringify(calls)}, mode = process.env.SENSITIVITY_TEST_MODE;
appendFileSync(calls, JSON.stringify({ home, cwd: process.cwd(), args: process.argv.slice(2) }) + '\\n');
if (process.argv[2] === '--version') { console.log(mode === 'version' ? '1.0.99' : '1.0.9'); process.exit(0); }
if (process.argv[2] === 'policies') {
  if (existsSync(join(home, 'policies-config.json'))) process.exit(3);
  writeFileSync(join(home, 'VERSION'), '4'); console.log('initialized'); process.exit(0);
}
const input = JSON.parse(readFileSync(0, 'utf8'));
appendFileSync(calls, JSON.stringify({ home, input }) + '\\n');
if (input.cwd !== process.cwd() || process.env.CLAUDE_PROJECT_DIR !== input.cwd ||
    readFileSync(join(home, 'policies-config.json'), 'utf8') !== ${JSON.stringify(configBytes)}) process.exit(4);
const manifest = JSON.parse(readFileSync(join(process.env.FAILPROOFAI_PACK_DIR, 'installed.json'), 'utf8'));
const pack = manifest.packs[0], names = pack.policies.map(p => p.name);
const enabled = mode === 'ignore-selection' ? names : pack.enabled ?? names;
const command = input.tool_input.command || '', path = input.tool_input.file_path;
const target = command.startsWith('sudo ') ? 'block-sudo' : command.includes('/chaos-sensitivity-') ? 'block-read-outside-cwd' : 'block-env-files';
const active = enabled.includes(target), mutated = !enabled.includes('block-env-files');
const isCanary = ['cat .env', 'sudo echo chaos-sensitivity'].includes(command) || command.includes('/chaos-sensitivity-');
if (mode === 'base-error' || (mode === 'candidate-error' && mutated && path === 'public.json')) process.exit(1);
if (mode === 'mutate-source' && mutated && !isCanary) writeFileSync(${JSON.stringify(userConfig)}, '{}');
let deny = active && (path === '.env' || isCanary);
if (mode === 'base-failure' && !isCanary) deny = false;
if (mode === 'overlap' && (path === '.env' || isCanary)) deny = true;
if (mode === 'unrelated' && command === 'other-check') deny = !mutated;
if (mode === 'benign-failure' && path === 'public.json') deny = mutated;
const policyName = 'pack/' + pack.id + '@' + pack.version + '/' + target;
const matchedPolicies = active ? [policyName] : [];
if (mode !== 'missing-activity') {
  mkdirSync(join(home, 'hook-activity'), { recursive: true });
  const activity = { sessionId: input.session_id, integration: process.argv.at(-1), eventType: input.hook_event_name,
    cwd: input.cwd, matchedPolicies, policyName: deny ? (mode === 'overlap' ? 'other-guard' : policyName) : null };
  if (mode === 'wrong-session') activity.sessionId = 'stale-session';
  appendFileSync(join(home, 'hook-activity', 'current.jsonl'), JSON.stringify(activity) + '\\n');
}
if (deny) console.log(JSON.stringify({ decision: 'block', reason: 'synthetic guard' }));
`, { mode: 0o755 });

  const detected = run();
  assert.equal(detected.status, 0, detected.stderr);
  assert.equal(detected.report.base.status, "passed");
  assert.deepEqual(detected.report.summary, { detected: 1, missed: 0, unsupported: 0, invalid: 0 });
  assert.deepEqual(detected.report.checks[0].mismatches.map((row) => row.id), ["env-read"]);
  assert.deepEqual(detected.report.checks[0].verification.before, { actual: "DENY", selected: true, attributed: true });
  assert.deepEqual(detected.report.checks[0].verification.after, { actual: "ALLOW", selected: false, attributed: false });
  assert.equal(detected.report.sourceContext.projectRoot, project);
  assert.equal(statSync(detected.output).mode & 0o777, 0o600);
  assert.doesNotMatch(JSON.stringify(detected.report), /sample-private-config-value/);
  assert.equal(readFileSync(manifestFile, "utf8"), JSON.stringify(manifest));
  assert.equal(readFileSync(userConfig, "utf8"), configBytes);
  assert.equal(readFileSync(join(home, "VERSION"), "utf8"), "source version sentinel");
  for (const [name, expected] of [["baseline.json", "baseline sentinel"], ["results.json", "results sentinel"], ["REPORT.md", "report sentinel"]])
    assert.equal(readFileSync(join(cwd, name), "utf8"), expected);
  assert.ok(entries().filter((row) => row.input).every((row) => row.input.cwd === cwd));
  assert.equal(run({ extra: ["--adapter", "codex"] }).status, 0);
  assert.equal(run({ selected: [targets[0], targets[0]] }).report.checks.length, 1);

  for (const options of [{ cases: [benign] }, { mode: "overlap" },
    { mode: "unrelated", cases: [benign, probe("unrelated", targets[1], { command: "other-check" })] },
    { mode: "benign-failure", cases: [benign] }]) {
    const result = run(options);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.report.checks[0].status, "missed");
  }
  for (const mode of ["base-error", "candidate-error", "missing-activity", "wrong-session", "ignore-selection"]) {
    const result = run({ mode });
    assert.equal(result.status, 2, mode);
    assert.equal(result.report.checks[0].status, "invalid", mode);
    if (mode === "candidate-error") assert.deepEqual(result.report.checks[0].mismatches.map((row) => row.actual), ["ALLOW", "ERROR"]);
  }
  const beforeFailed = entries().length;
  const failed = run({ mode: "base-failure" });
  assert.equal(failed.status, 2);
  assert.equal(failed.report.base.status, "failed");
  assert.equal(entries().slice(beforeFailed).filter((row) => row.input).length, 2, "A failing base must stop before canary and weakened runs");
  for (const options of [{ selected: ["not-supported"] }, { mode: "version" }, { env: { FAILPROOFAI_CLOUD_POLICY_DIR: root } }]) {
    const result = run(options);
    assert.equal(result.status, 2);
    assert.equal(result.report.checks[0].status, "unsupported");
  }
  writeJSON(manifestFile, { ...manifest, packs: [{ ...manifest.packs[0], enabled: [] }] });
  const disabled = run({ cases: [benign] });
  assert.equal(disabled.status, 2);
  assert.equal(disabled.report.checks[0].status, "unsupported");
  writeJSON(manifestFile, manifest);
  writeFileSync(artifact, "tampered");
  assert.equal(run().status, 2);
  writeFileSync(artifact, bytes);
  const mutated = run({ mode: "mutate-source" });
  assert.equal(mutated.status, 2);
  assert.match(mutated.report.checks[0].reason, /Source files changed/);
  writeFileSync(userConfig, configBytes);

  const existing = join(root, "existing.json");
  writeFileSync(existing, '{}');
  symlinkSync(suite, join(root, "suite-link.json"));
  linkSync(suite, join(root, "suite-hardlink.json"));
  symlinkSync(join(root, "missing.json"), join(root, "dangling.json"));
  symlinkSync(join(project, ".failproofai"), join(root, "config-alias"));
  const callCount = entries().length;
  for (const out of [suite, existing, join(root, "suite-link.json"), join(root, "suite-hardlink.json"), join(root, "dangling.json"),
    join(project, ".failproofai", "policies-config.json"), join(root, "config-alias", "policies-config.local.json")]) {
    assert.equal(run({ out }).status, 2, out);
  }
  assert.equal(entries().length, callCount, "Unsafe output paths must be rejected before engine calls");
  assert.equal(existsSync(join(root, "missing.json")), false);
  assert.equal(existsSync(join(project, ".failproofai", "policies-config.json")), false);
  assert.equal(readFileSync(existing, "utf8"), '{}');
  const missingConfig = join(root, "missing-user-config.json");
  rmSync(userConfig);
  symlinkSync(missingConfig, userConfig);
  assert.equal(run({ out: missingConfig }).status, 2);
  assert.equal(existsSync(missingConfig), false);
  rmSync(userConfig);
  writeFileSync(userConfig, configBytes);
  for (const path of [join(home, "VERSION"), join(home, "policies-config.local.json"), join(home, "config.json"), join(home, "jev.json"), artifact,
    join(home, "credentials.json"), join(home, "settings.json"), join(project, ".failproofai", "settings.json")]) {
    const original = existsSync(path) ? readFileSync(path) : null;
    rmSync(path, { force: true });
    const missing = join(root, `missing-source-${runNumber++}.json`);
    symlinkSync(missing, path);
    assert.equal(run({ out: missing }).status, 2, path);
    assert.equal(existsSync(missing), false, "A report must not create an absent source through a dangling alias");
    rmSync(path);
    if (original) writeFileSync(path, original);
  }
  console.log("Sensitivity checks passed: attribution, missed/unsupported/invalid results, source preservation, and temporary cleanup.");
} finally {
  rmSync(root, { recursive: true, force: true });
}
