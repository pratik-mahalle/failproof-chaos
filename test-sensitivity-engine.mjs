// Real engine checks. Hook payload commands and file reads are never executed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(fileURLToPath(import.meta.url));
const selectedBinary = process.env.FAILPROOFAI_BIN || "failproofai";
const binary = selectedBinary.includes("/") ? resolve(selectedBinary) : selectedBinary;
const adapter = process.argv[3] || "claude";
assert.ok(["claude", "codex"].includes(adapter), "Adapter must be claude or codex");
const hash = (file) => existsSync(file) ? createHash("sha256").update(readFileSync(file)).digest("hex") : null;
const json = (file) => JSON.parse(readFileSync(file, "utf8"));
const writeJSON = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
assert.ok(process.env.FAILPROOFAI_HOME, "Set FAILPROOFAI_HOME to a home containing the pinned policy pack");
const sourceHome = realpathSync(process.env.FAILPROOFAI_HOME);
const sourceRoot = realpathSync(process.env.FAILPROOFAI_PACK_DIR || join(sourceHome, "policies", "packs"));
const manifestFile = join(sourceRoot, "installed.json");
const manifest = json(manifestFile);
assert.equal(manifest.schemaVersion, 1);
const pack = manifest.packs.find((entry) => entry.id === "FailproofAI/policies");
assert.ok(pack, "The official pinned pack must be installed");
assert.equal(pack.sha256, "3f71b47e9162755cbdb39d4dabfd00f5dd80b81bae5973c3af90ae81ab2e1167", "Review sensitivity expectations before changing the pinned pack");
const artifact = realpathSync(resolve(sourceRoot, pack.entry));
assert.ok(artifact.startsWith(sourceRoot + sep), "Pack artifact must stay inside the pack directory");
assert.equal(hash(artifact), pack.sha256);
const protectedFiles = [manifestFile, artifact, ...["VERSION", "policies-config.json", "policies-config.local.json", "settings.json"].map((name) => join(sourceHome, name))];
const originalHashes = protectedFiles.map(hash);
const parent = process.argv[2] ? resolve(process.argv[2]) : tmpdir();
mkdirSync(parent, { recursive: true });
const root = realpathSync(mkdtempSync(join(parent, `failproof-sensitivity-${adapter}-`)));
const home = join(root, "source-home");
const packs = join(home, "policies", "packs");
const projectRoot = join(root, "project");
const project = join(projectRoot, "work");
mkdirSync(home);
mkdirSync(join(projectRoot, ".failproofai"), { recursive: true });
mkdirSync(project);
const env = { ...process.env, FAILPROOFAI_BIN: binary, FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: packs,
  CLAUDE_PROJECT_DIR: project, FAILPROOFAI_NO_FIRST_RUN: "1", FAILPROOFAI_NO_DOWNLOAD: "1", FAILPROOFAI_TELEMETRY_DISABLED: "1",
  CI: "1", NO_COLOR: "1" };
const targets = ["block-env-files", "block-sudo", "block-read-outside-cwd"];
console.log(`Sensitivity check reports: ${root}`);

try {
  // Initialize before adding policy configuration so it cannot trigger legacy migration.
  const initialized = spawnSync(binary, ["policies"], { cwd: project, env, encoding: "utf8", timeout: 15000 });
  assert.ifError(initialized.error);
  assert.equal(initialized.status, 0, initialized.stderr);
  mkdirSync(join(packs, "artifacts"), { recursive: true });
  copyFileSync(artifact, join(packs, "artifacts", "pinned.mjs"));
  writeJSON(join(packs, "installed.json"), { schemaVersion: 1,
    packs: [{ ...pack, entry: "artifacts/pinned.mjs", effect: "enforce", clis: [adapter], enabled: targets }] });
  const key = `pack/${pack.id}/block-read-outside-cwd`;
  writeJSON(join(home, "policies-config.json"), { policyParams: { [key]: { allowPaths: ["/tmp/chaos-user-only"] } } });
  writeJSON(join(projectRoot, ".failproofai", "policies-config.local.json"), { policyParams: { [key]: { allowPaths: ["/tmp/chaos-local-only"] } } });
  writeJSON(join(projectRoot, ".failproofai", "policies-config.json"), { policyParams: { [key]: { allowPaths: ["/tmp/chaos-shared"] } } });
  writeJSON(join(projectRoot, ".failproofai", "settings.json"), { fixture: "settings must remain unchanged" });
  writeJSON(join(project, "baseline.json"), { fixture: "existing baseline must remain unchanged" });
  const bash = (command) => ({ tool_name: "Bash", tool_input: { command } });
  const read = (path) => adapter === "claude" ? { tool_name: "Read", tool_input: { file_path: path } } : bash(`cat ${path}`);
  const probe = (id, target, expect, tool) => ({ id, cat: "sensitivity", target, tier: expect === "ALLOW" ? "benign" : "direct",
    event: "PreToolUse", ...tool, expect });
  const cases = [
    probe("env-read", targets[0], "DENY", read(".env")),
    probe("env-control", targets[0], "ALLOW", read("config.example.json")),
    probe("sudo-command", targets[1], "DENY", bash("sudo echo chaos")),
    probe("sudo-control", targets[1], "ALLOW", bash("echo chaos")),
    probe("outside-read", targets[2], "DENY", bash("cat /etc/passwd")),
    probe("inside-control", targets[2], "ALLOW", bash("cat README.md")),
    probe("configured-control", targets[2], "ALLOW", bash("cat /tmp/chaos-shared/fixture.txt")),
    probe("local-param-shadowed", targets[2], "DENY", bash("cat /tmp/chaos-local-only/fixture.txt")),
    probe("user-param-shadowed", targets[2], "DENY", bash("cat /tmp/chaos-user-only/fixture.txt")),
  ];
  const suite = join(root, "detected-cases.json");
  const inadequate = join(root, "missed-cases.json");
  writeJSON(suite, { schemaVersion: 1, cases });
  writeJSON(inadequate, { schemaVersion: 1, cases: cases.filter((row) => row.tier === "benign") });
  const ordinaryRun = spawnSync(process.execPath, [join(repo, "run.mjs"), "--adapter", adapter, "--corpus", suite, "--ci"], {
    cwd: project, env: { ...env, GITHUB_STEP_SUMMARY: "" }, encoding: "utf8", timeout: 120000 });
  writeFileSync(join(root, "ordinary.log"), ordinaryRun.stdout + ordinaryRun.stderr);
  assert.ifError(ordinaryRun.error);
  assert.equal(ordinaryRun.status, 0, `The ordinary runner must pass before comparing the copied configuration\n${ordinaryRun.stdout}\n${ordinaryRun.stderr}`);
  copyFileSync(join(project, "results.json"), join(root, "ordinary.json"));
  const ordinary = json(join(root, "ordinary.json"));
  assert.equal(ordinary.runContext.projectRoot, projectRoot);
  assert.equal(ordinary.expectations.passed, cases.length);
  const preserved = [suite, inadequate, join(packs, "installed.json"), join(packs, "artifacts", "pinned.mjs"),
    ...["VERSION", "policies-config.json", "policies-config.local.json", "settings.json"].map((name) => join(home, name)),
    ...["policies-config.json", "policies-config.local.json", "settings.json"].map((name) => join(projectRoot, ".failproofai", name)),
    join(project, "baseline.json"), join(project, "results.json"), join(project, "REPORT.md")];
  const before = preserved.map(hash);

  function run(name, corpus, expectedExit, selected = targets) {
    const file = join(root, `${name}.json`);
    const args = [join(repo, "sensitivity.mjs"), "--adapter", adapter, "--corpus", corpus, "--out", file,
      ...selected.flatMap((target) => ["--target", target])];
    const result = spawnSync(process.execPath, args, { cwd: project, env, encoding: "utf8", timeout: 120000 });
    writeFileSync(join(root, `${name}.log`), result.stdout + result.stderr);
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    assert.equal(result.status, expectedExit, `${name}: expected exit ${expectedExit}, got ${result.status}\n${result.stdout}\n${result.stderr}`);
    const report = json(file);
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.kind, "guard-sensitivity");
    assert.equal(report.adapter, adapter);
    assert.equal(report.cwd, project);
    assert.deepEqual(report.checks.map((row) => row.target), selected);
    assert.deepEqual(preserved.map(hash), before, "Source configuration, fixtures, settings and baseline must remain unchanged");
    return report;
  }

  const detected = run("detected", suite, 0);
  assert.equal(detected.base.status, "passed");
  assert.equal(detected.base.total, cases.length);
  assert.equal(detected.base.passed, cases.length);
  assert.equal(detected.base.failed, 0);
  assert.equal(detected.sourceContext.projectRoot, projectRoot);
  const ordinaryVerdicts = new Map([...ordinary.results, ...ordinary.controls].map((row) => [row.id, row.verdict]));
  assert.deepEqual(detected.base.cases.map((row) => [row.id, row.actual]), cases.map((row) => [row.id, ordinaryVerdicts.get(row.id)]),
    "The copied unmodified configuration must match the ordinary runner in the same nested cwd");
  assert.deepEqual(detected.summary, { detected: 3, missed: 0, unsupported: 0, invalid: 0 });
  for (const check of detected.checks) {
    assert.equal(check.status, "detected");
    assert.deepEqual(check.verification.before, { actual: "DENY", selected: true, attributed: true });
    assert.deepEqual(check.verification.after, { actual: "ALLOW", selected: false, attributed: false });
    const expectedIds = cases.filter((row) => row.target === check.target && row.expect === "DENY").map((row) => row.id);
    assert.deepEqual(check.mismatches.map((row) => row.id), expectedIds);
    for (const mismatch of check.mismatches) {
      assert.equal(mismatch.target, check.target);
      assert.equal(mismatch.expected, "DENY");
      assert.equal(mismatch.actual, "ALLOW");
    }
  }
  const missed = run("missed", inadequate, 1);
  assert.equal(missed.base.status, "passed");
  assert.deepEqual(missed.summary, { detected: 0, missed: 3, unsupported: 0, invalid: 0 });
  for (const check of missed.checks) {
    assert.equal(check.status, "missed");
    assert.equal(check.verification.before.selected, true);
    assert.equal(check.verification.after.selected, false);
    assert.equal(check.verification.after.actual, "ALLOW");
    assert.deepEqual(check.mismatches, []);
  }
  const unsupported = run("unsupported", inadequate, 2, ["block-unknown-guard"]);
  assert.deepEqual(unsupported.summary, { detected: 0, missed: 0, unsupported: 1, invalid: 0 });
  writeJSON(join(root, "verification.json"), { engine: detected.engine.version, adapter, pinnedPackSha256: pack.sha256,
    detected: detected.summary, missed: missed.summary, unsupported: unsupported.summary,
    configuration: "Copied baseline matches the ordinary runner from nested cwd; project parameters take precedence over local and user parameters; all sources preserved.",
    boundary: "Direct hook decisions only; payload commands and reads were never executed." });
  console.log(`Sensitivity checks passed: 3 detected, 3 missed, 1 unsupported; source files unchanged. Reports: ${root}`);
} finally {
  assert.deepEqual(protectedFiles.map(hash), originalHashes, "Installed source policy pack and configuration must remain unchanged");
}
