#!/usr/bin/env node
// Payloads are data. Only the installed hook engine evaluates them.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { classify } from "./adapter.mjs";
import { captureContext } from "./config-context.mjs";
import { validateCorpus } from "./suite.mjs";

const supported = ["block-env-files", "block-sudo", "block-read-outside-cwd"];
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const read = (path) => { try { return readFileSync(path); } catch (error) { if (error.code === "ENOENT") return null; throw error; } };
const canonical = (path) => lstatSync(path, { throwIfNoEntry: false }) ? realpathSync(path) : join(canonical(dirname(path)), basename(path));
const within = (path, dir) => path === dir || path.startsWith(dir + sep);
const fail = (message, status = "invalid") => { throw Object.assign(new Error(message), { status }); };
const json = (bytes, label) => { try { return JSON.parse(bytes); } catch { fail(`${label} must contain valid JSON`); } };
let temporary, output, report, snapshots = [];

function verifySources() {
  for (const { path, bytes } of snapshots) {
    const after = read(path);
    if (bytes === null ? after !== null : after === null || !bytes.equals(after))
      fail("A source configuration, artifact, or suite changed during the check; discard this measurement");
  }
}

function main() {
  const { values: options } = parseArgs({ options: { corpus: { type: "string" }, target: { type: "string", multiple: true },
    adapter: { type: "string", default: "claude" }, out: { type: "string" }, help: { type: "boolean", short: "h" } } });
  if (options.help) {
    console.log("Usage: node sensitivity.mjs --corpus suite.json --target policy [--target policy] [--adapter claude|codex] --out NEW.json\n" +
      `Supported targets: ${supported.join(", ")}. Requires a passing suite and a verified installed official pack.\n` +
      "Exit: 0 all detected, 1 missed changes, 2 unsupported/invalid or nonpassing base. No payload command is executed.");
    return;
  }
  for (const key of ["corpus", "out"]) if (!options[key]?.trim()) fail(`--${key} is required`);
  if (!options.target?.length || options.target.some((target) => !target.trim())) fail("At least one nonempty --target is required");
  if (!["claude", "codex"].includes(options.adapter)) fail("--adapter must be claude or codex");
  const cwd = process.cwd(), adapter = options.adapter;
  const corpus = resolve(options.corpus), destination = resolve(options.out);
  if (lstatSync(destination, { throwIfNoEntry: false })) fail("--out must be a new file, including no symlink at that path");
  const sourceHome = resolve(process.env.FAILPROOFAI_HOME || join(homedir(), ".failproofai"));
  const sourceRoot = resolve(process.env.FAILPROOFAI_PACK_DIR || join(sourceHome, "policies", "packs"));
  const context = captureContext({ cwd, adapter, mode: "combined" });
  const manifestBytes = read(context.manifest.path);
  const declared = context.manifest.status === "present" ? json(manifestBytes, "Installed manifest") : null;
  const tracked = [corpus, ...context.configFiles.map((file) => file.path), join(sourceHome, "policies-config.local.json"),
    join(sourceHome, "config.json"), join(sourceHome, "jev.json"), join(sourceHome, "VERSION"), context.manifest.path,
    ...(Array.isArray(declared?.packs) ? declared.packs.filter((pack) => typeof pack?.entry === "string").map((pack) => resolve(sourceRoot, pack.entry)) : [])];
  const dest = canonical(destination);
  const protectedDirs = [sourceHome, sourceRoot, join(context.projectRoot, ".failproofai")].map(canonical);
  const protectedFiles = [...tracked, join(sourceHome, "credentials.json"), join(sourceHome, "settings.json"),
    join(context.projectRoot, ".failproofai", "settings.json"), join(cwd, "results.json"), join(cwd, "REPORT.md")];
  if (protectedDirs.some((dir) => within(dest, dir)) || protectedFiles.map(canonical).includes(dest))
    fail("--out must be separate from source configuration, the suite, and benchmark reports");
  const suiteBytes = readFileSync(corpus);
  const cases = validateCorpus(json(suiteBytes, "Corpus"));
  output = destination;
  report = { schemaVersion: 1, kind: "guard-sensitivity", adapter, cwd,
    suite: { path: corpus, sha256: hash(suiteBytes) }, sourceContext: context,
    base: { status: "not-run", total: cases.length, passed: 0, failed: 0, cases: [] },
    checks: [...new Set(options.target)].map((target) => ({ target, status: "invalid", reason: "Not evaluated" })) };

  snapshots = [...new Set(tracked)].map((path) => ({ path, bytes: path === corpus ? suiteBytes : path === context.manifest.path ? manifestBytes : read(path) }));
  for (const file of [context.manifest, ...context.configFiles]) {
    const bytes = snapshots.find((source) => source.path === file.path)?.bytes;
    if (file.sha256 && (bytes === null || hash(bytes) !== file.sha256)) fail("Source files changed during configuration capture");
  }
  if (context.manifest.status !== "present" || !context.packs?.length || context.packs.some((pack) => pack.artifact?.status !== "verified"))
    fail("Installed manifest and every artifact must be readable and SHA-256 verified");
  const manifest = json(snapshots.find((source) => source.path === context.manifest.path).bytes, "Installed manifest");
  if (manifest.packs.length !== 1 || manifest.packs[0].id !== "FailproofAI/policies")
    fail("Only one installed FailproofAI/policies pack is supported", "unsupported");
  const pack = manifest.packs[0];
  if (!Array.isArray(pack.policies) || !pack.policies.length || pack.policies.some((policy) => !object(policy) || typeof policy.name !== "string") ||
      new Set(pack.policies.map((policy) => policy.name)).size !== pack.policies.length)
    fail("Installed pack must have a nonempty, unique policy catalog");
  if (pack.semantic?.length) fail("Semantic policies are not supported by this copied configuration check", "unsupported");
  const names = pack.policies.map((policy) => policy.name);
  if (pack.enabled?.some((name) => !names.includes(name))) fail("Enabled policy is absent from the pack catalog");
  const enabled = pack.enabled ?? names;
  if ((pack.effect ?? "enforce") !== "enforce" || (pack.clis && !pack.clis.includes(adapter)))
    fail("The installed pack must enforce for the selected adapter", "unsupported");
  const artifact = context.packs[0].artifact.path, artifactBytes = readFileSync(artifact);
  if (hash(artifactBytes) !== pack.sha256) fail("Policy artifact changed or failed its SHA-256 integrity check");
  snapshots.push({ path: artifact, bytes: artifactBytes });
  for (const source of context.configFiles) {
    if (source.status === "missing") continue;
    if (source.status !== "present") fail("Policy configuration must be readable JSON");
    const config = json(snapshots.find((file) => file.path === source.path).bytes, "Policy configuration");
    if (Object.keys(config).some((key) => !["enabledPolicies", "policyParams", "disabledCustomPolicies", "customPoliciesEnabled"].includes(key)))
      fail("Custom, semantic, or unknown policy configuration fields are unsupported", "unsupported");
    for (const key of ["enabledPolicies", "disabledCustomPolicies"])
      if (config[key] !== undefined && (!Array.isArray(config[key]) || config[key].some((value) => typeof value !== "string")))
        fail(`Policy configuration ${key} must be an array of strings`);
    if (config.policyParams !== undefined && (!object(config.policyParams) || Object.values(config.policyParams).some((value) => !object(value))))
      fail("Policy configuration policyParams must contain objects");
    if (config.customPoliciesEnabled !== undefined && typeof config.customPoliciesEnabled !== "boolean")
      fail("Policy configuration customPoliciesEnabled must be boolean");
  }
  for (const path of [join(sourceHome, "config.json"), join(sourceHome, "jev.json")])
    if (existsSync(path)) fail("Homes with config.json or jev.json require unsupported settings beyond installed packs", "unsupported");
  for (const path of [join(context.projectRoot, ".failproofai", "policies"), join(sourceHome, "policies")]) {
    if (!existsSync(path)) continue;
    if (readdirSync(path).some((name) => resolve(path, name) !== resolve(sourceRoot)))
      fail("Custom, convention, or cloud policy files are unsupported", "unsupported");
  }
  const allowedEnv = ["FAILPROOFAI_BIN", "FAILPROOFAI_HOME", "FAILPROOFAI_PACK_DIR", "FAILPROOFAI_NO_FIRST_RUN", "FAILPROOFAI_NO_DOWNLOAD", "FAILPROOFAI_TELEMETRY_DISABLED"];
  if (Object.keys(process.env).some((key) => key.startsWith("FAILPROOFAI_") && !allowedEnv.includes(key)))
    fail("Additional FAILPROOFAI environment overrides are unsupported", "unsupported");
  if (process.env.CLAUDE_PROJECT_DIR && resolve(process.env.CLAUDE_PROJECT_DIR) !== cwd)
    fail("CLAUDE_PROJECT_DIR must match the tested cwd", "unsupported");

  temporary = realpathSync(mkdtempSync(join(tmpdir(), "failproof-sensitivity-")));
  const home = join(temporary, "home"), packs = join(home, "policies", "packs");
  mkdirSync(home);
  const binary = process.env.FAILPROOFAI_BIN || "failproofai";
  const bin = binary.includes("/") ? resolve(binary) : binary;
  const env = { ...process.env, CI: "1", NO_COLOR: "1", FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: packs,
    CLAUDE_PROJECT_DIR: cwd, FAILPROOFAI_NO_FIRST_RUN: "1", FAILPROOFAI_NO_DOWNLOAD: "1", FAILPROOFAI_TELEMETRY_DISABLED: "1" };
  const invoke = (args, input, testedCwd = cwd) => spawnSync(bin, args, { input, cwd: testedCwd, env, encoding: "utf8", timeout: 15000 });
  const version = invoke(["--version"], undefined, temporary);
  if (version.error || version.signal || version.status !== 0) fail("Engine version probe failed");
  report.engine = { binary: bin, version: version.stdout.trim() };
  if (!/^(?:failproofai\s+)?1\.0\.(?:3|9|10)$/.test(report.engine.version)) fail("Supported engine versions are 1.0.3, 1.0.9, and 1.0.10", "unsupported");
  // Initialize first: installing config in an uninitialized home can trigger legacy migration.
  const initialized = invoke(["policies"], undefined, temporary);
  if (initialized.error || initialized.signal || initialized.status !== 0) fail("Temporary engine home initialization failed");
  mkdirSync(join(packs, "artifacts"), { recursive: true });
  writeFileSync(join(packs, "artifacts", "installed.mjs"), artifactBytes, { mode: 0o600 });
  const userConfig = snapshots.find((source) => source.path === context.configFiles[2].path)?.bytes;
  if (userConfig !== null && userConfig !== undefined) writeFileSync(join(home, "policies-config.json"), userConfig, { mode: 0o600 });
  const copiedManifest = { ...manifest, packs: [{ ...pack, entry: "artifacts/installed.mjs" }] };
  const manifestFile = join(packs, "installed.json");
  const select = (target) => {
    copiedManifest.packs[0] = { ...pack, entry: "artifacts/installed.mjs", ...(target ? { enabled: enabled.filter((name) => name !== target) } : {}) };
    writeFileSync(manifestFile, JSON.stringify(copiedManifest), { mode: 0o600 });
  };
  const evaluate = (c, activity = false) => {
    const session = `chaos-sensitivity-${randomUUID()}`;
    const payload = { session_id: session, cwd, hook_event_name: c.event, tool_name: c.tool_name, tool_input: c.tool_input,
      ...(c.tool_response !== undefined ? { tool_response: c.tool_response } : {}) };
    const result = classify(c.event, invoke(["--hook", c.event, "--cli", adapter], JSON.stringify(payload)), adapter);
    if (!activity) return { id: c.id, target: c.target, tier: c.tier, expected: c.expect, actual: result.verdict };
    let entries;
    try { entries = readFileSync(join(home, "hook-activity", "current.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((row) => row.sessionId === session); }
    catch { return { actual: result.verdict, valid: false }; }
    const row = entries[0], policyName = `pack/${pack.id}@${pack.version}/${c.target}`;
    const valid = entries.length === 1 && row.integration === adapter && row.eventType === c.event && row.cwd === cwd &&
      Array.isArray(row.matchedPolicies) && row.matchedPolicies.every((name) => typeof name === "string");
    return { actual: result.verdict, valid, selected: valid && row.matchedPolicies.includes(policyName), attributed: valid && row.policyName === policyName };
  };
  select();
  const baseCases = cases.map((c) => evaluate(c));
  const failures = baseCases.filter((row) => row.actual !== row.expected);
  report.base = { status: baseCases.some((row) => row.actual === "ERROR") ? "invalid" : failures.length ? "failed" : "passed",
    total: cases.length, passed: cases.length - failures.length, failed: failures.length, cases: baseCases };
  if (report.base.status !== "passed") fail("The unmodified suite must pass before checking weakened guards");
  for (const check of report.checks) {
    const target = check.target;
    if (!supported.includes(target) || !enabled.includes(target)) {
      Object.assign(check, { status: "unsupported", reason: "Target must be supported, installed, and enabled" });
      continue;
    }
    const outside = `/chaos-sensitivity-${randomUUID()}/fixture.txt`;
    if (target === "block-read-outside-cwd" && dirname(cwd) === cwd) {
      Object.assign(check, { status: "unsupported", reason: "An outside-cwd canary cannot be constructed when cwd is the filesystem root" });
      continue;
    }
    const canary = { target, event: "PreToolUse", tool_name: "Bash", tool_input: { command:
      target === "block-env-files" ? "cat .env" : target === "block-sudo" ? "sudo echo chaos-sensitivity" : `cat ${outside}` } };
    select();
    const before = evaluate(canary, true);
    select(target);
    const after = evaluate(canary, true);
    const evidence = (row) => ({ actual: row.actual, selected: row.selected ?? false, attributed: row.attributed ?? false });
    check.verification = { policyName: `pack/${pack.id}@${pack.version}/${target}`, before: evidence(before), after: evidence(after) };
    if ([before, after].some((row) => !row.valid || row.actual === "ERROR") || after.selected) {
      Object.assign(check, { status: "invalid", reason: "Engine activity did not verify selection before and removal after the change" });
      continue;
    }
    if (!before.selected) {
      Object.assign(check, { status: "unsupported", reason: "The engine did not select this guard in the unmodified configuration" });
      continue;
    }
    const changed = cases.map((c) => evaluate(c));
    check.relevantCases = changed.filter((row) => row.target === target && row.tier !== "benign").map((row) => row.id);
    check.mismatches = changed.filter((row) => row.actual !== row.expected);
    if (changed.some((row) => row.actual === "ERROR")) {
      Object.assign(check, { status: "invalid", reason: "The weakened run contains an engine error" });
    } else if (check.mismatches.some((row) => row.target === target && row.tier !== "benign")) {
      Object.assign(check, { status: "detected", reason: "A relevant nonbenign case failed its exact expectation" });
    } else {
      Object.assign(check, { status: "missed", reason: "No relevant expectation exposed this change; investigate missing coverage or overlapping protection" });
    }
  }
}

try { main(); } catch (error) {
  const message = error.status ? error.message : `Check failed (${error.code || "unexpected error"})`;
  console.error(message);
  if (report) report.checks = report.checks.map(({ target }) => ({ target, status: error.status || "invalid", reason: message }));
  process.exitCode = 2;
} finally {
  try { verifySources(); } catch {
    if (report) report.checks = report.checks.map(({ target }) => ({ target, status: "invalid", reason: "Source files changed during this measurement" }));
    process.exitCode = 2;
  }
  if (temporary) {
    try { rmSync(temporary, { recursive: true, force: true }); } catch {
      if (report) report.checks = report.checks.map(({ target }) => ({ target, status: "invalid", reason: "Temporary state cleanup failed" }));
      process.exitCode = 2;
    }
  }
  if (report) {
    report.summary = Object.fromEntries(["detected", "missed", "unsupported", "invalid"].map((status) => [status, report.checks.filter((check) => check.status === status).length]));
    process.exitCode = report.base.status !== "passed" || report.summary.invalid || report.summary.unsupported ? 2 : report.summary.missed ? 1 : 0;
    try {
      writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { flag: "wx", mode: 0o600 });
      console.log(`Guard sensitivity: ${report.summary.detected} detected, ${report.summary.missed} missed, ${report.summary.unsupported} unsupported, ${report.summary.invalid} invalid. ${output}`);
    } catch { console.error("Could not write the new sensitivity report; existing files were left intact"); process.exitCode = 2; }
  }
}
