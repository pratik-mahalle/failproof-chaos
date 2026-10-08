#!/usr/bin/env node
// Break a temporary copy of the installed pack, one fault at a time, and check the attack is still refused.
// Payloads are data; the source home is read, never written.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { classify } from "./adapter.mjs";
import { CORPUS, CONTROLS } from "./corpus.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const binary = process.env.FAILPROOFAI_BIN || "failproofai";
const BIN = binary.includes("/") ? resolve(binary) : binary;
const env = { ...process.env, CI: "1", NO_COLOR: "1", FAILPROOFAI_NO_FIRST_RUN: "1",
  FAILPROOFAI_NO_DOWNLOAD: "1", FAILPROOFAI_TELEMETRY_DISABLED: "1" };
const fail = (message) => { throw new Error(message); };

const HEAD = 'import { customPolicies, deny, allow } from "failproofai";\n';
const probe = (decl, fn) => `customPolicies.add({ name: ${JSON.stringify(decl.name)}, description: "fault probe", match: ${JSON.stringify(decl.match)}, fn: ${fn} });\n`;
const denies = (attack) => `async (ctx) => ctx.toolInput?.command === ${JSON.stringify(attack.tool_input.command)} ? deny("fault probe") : allow()`;

// Re-signed faults keep a valid SHA-256 so they test behavior, not tamper detection.
// documentedOpen: upstream treats the state as intentional; OPEN is reported but does not fail.
const FAULTS = [
  { id: "healthy", stage: "control", note: "unmodified copy of the installed pack", apply() {} },
  { id: "healthy-synthetic", stage: "control", note: "re-signed probe policy that denies the attack", apply: (s) => s.sign(HEAD + probe(s.decl, denies(s.attack))) },
  { id: "manifest-unreadable", stage: "load", note: "installed.json is not JSON", apply: (s) => writeFileSync(s.manifest, "{not json") },
  { id: "manifest-invalid", stage: "load", note: "installed.json is an empty object", apply: (s) => writeFileSync(s.manifest, "{}") },
  { id: "artifact-hash-mismatch", stage: "load", note: "artifact bytes differ from the declared SHA-256", apply: (s) => appendFileSync(s.artifact, "\n// fault probe: tampered\n") },
  { id: "artifact-missing", stage: "load", note: "declared artifact is deleted", apply: (s) => rmSync(s.artifact) },
  { id: "artifact-load-throws", stage: "load", note: "re-signed module throws on import", apply: (s) => s.sign(HEAD + 'throw new Error("fault probe: load failure");\n') },
  { id: "artifact-load-timeout", stage: "load", note: "re-signed module loads for 3 s; FAILPROOFAI_POLICY_LOAD_TIMEOUT_MS=500 (CLOSED if the engine ignores the override)",
    env: { FAILPROOFAI_POLICY_LOAD_TIMEOUT_MS: "500" }, apply: (s) => s.sign(HEAD + "await new Promise((done) => setTimeout(done, 3000));\n" + probe(s.decl, denies(s.attack))) },
  { id: "policy-throws", stage: "runtime", note: "target policy throws", apply: (s) => s.sign(HEAD + probe(s.decl, 'async () => { throw new Error("fault probe: runtime failure"); }')) },
  { id: "policy-invalid-result", stage: "runtime", note: "target policy returns a non-decision", apply: (s) => s.sign(HEAD + probe(s.decl, "async () => 42")) },
  { id: "policy-hangs", stage: "runtime", note: "target policy never settles (engine waits about 10 s)", apply: (s) => s.sign(HEAD + probe(s.decl, "() => new Promise(() => {})")) },
  { id: "policy-not-registered", stage: "runtime", note: "pack declares the target but registers nothing", apply: (s) => s.sign(HEAD) },
  { id: "manifest-absent", stage: "load", documentedOpen: true, note: "upstream treats a missing manifest as a fresh machine", apply: (s) => rmSync(s.manifest) },
];

function measure(fault, ctx) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "failproof-fault-")));
  try {
    const home = join(root, ".failproofai"); // Also the project marker, as in run.mjs isolation.
    const dir = join(home, "policies", "packs");
    mkdirSync(join(dir, "artifacts"), { recursive: true });
    const manifest = join(dir, "installed.json"), artifact = join(dir, "artifacts", "0.mjs");
    const entry = { ...ctx.pack, entry: "artifacts/0.mjs", effect: "enforce", clis: ["claude"], enabled: [ctx.target] };
    writeFileSync(artifact, ctx.artifactBytes);
    writeFileSync(manifest, JSON.stringify({ schemaVersion: 1, packs: [entry] }));
    fault.apply({ manifest, artifact, decl: ctx.decl, attack: ctx.attack, sign(code) {
      writeFileSync(artifact, code);
      writeFileSync(manifest, JSON.stringify({ schemaVersion: 1, packs: [{ ...entry, sha256: hash(code), policies: [ctx.decl] }] }));
    } });
    const call = (c) => classify(c.event, spawnSync(BIN, ["--hook", c.event, "--cli", "claude"], {
      cwd: root, encoding: "utf8", timeout: 30000,
      input: JSON.stringify({ session_id: "chaos-fault", cwd: root, hook_event_name: c.event, tool_name: c.tool_name, tool_input: c.tool_input }),
      env: { ...env, ...fault.env, FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: dir, CLAUDE_PROJECT_DIR: root },
    }), "claude", { failClosed: true });
    const attack = call(ctx.attack), control = call(ctx.control);
    const outcome = attack.verdict === "ERROR" || control.verdict === "ERROR" ? "ERROR"
      : ["DENY", "ASK"].includes(attack.verdict) ? "CLOSED" : "OPEN";
    return { id: fault.id, stage: fault.stage, documentedOpen: fault.documentedOpen ?? false, note: fault.note,
      attack: attack.verdict, control: control.verdict, outcome, reason: String(attack.reason).slice(0, 300) };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function readBaseline(path, target) {
  let data;
  try { data = JSON.parse(readFileSync(path, "utf8")); } catch { fail("--baseline must be a readable JSON fault report"); }
  if (data?.schemaVersion !== 1 || data.kind !== "fault-injection" || !Array.isArray(data.faults)) fail("--baseline must be a schema-1 fault report");
  if (data.target !== target) fail("Baseline target must match --target");
  // An invalid prior report would hide regressions (ERROR -> OPEN is not CLOSED -> OPEN).
  if (data.faults.some((f) => typeof f?.id !== "string" || !["CLOSED", "OPEN", "ERROR"].includes(f.outcome) || f.outcome === "ERROR" ||
    (f.stage === "control" && f.outcome !== "CLOSED"))) fail("--baseline must be a valid fault report without errors or unhealthy controls");
  return new Map(data.faults.map((f) => [f.id, f.outcome]));
}

function main() {
  const { values: o } = parseArgs({ options: { target: { type: "string", default: "block-sudo" }, out: { type: "string" },
    baseline: { type: "string" }, help: { type: "boolean", short: "h" } } });
  if (o.help) {
    console.log("Usage: node faults.mjs --out NEW.json [--target block-sudo] [--baseline previous.json]\n" +
      "Copies the installed pack into a temporary home, injects one fault at a time, and checks the target's built-in attack is still refused.\n" +
      "Exit: 0 no new fail-open, 1 fail-open (or CLOSED->OPEN against --baseline), 2 invalid measurement. No payload command is executed.");
    return 0;
  }
  if (!o.out?.trim()) fail("--out is required");
  const out = resolve(o.out);
  if (lstatSync(out, { throwIfNoEntry: false })) fail("--out must be a new file");
  // The synthetic probe policy matches on the Bash command, the form verified against the engine.
  const attack = CORPUS.find((c) => c.target === o.target && c.tier === "direct" && c.event === "PreToolUse" && c.tool_name === "Bash");
  const control = CONTROLS.find((c) => c.target === o.target && c.event === "PreToolUse" && c.tool_name === "Bash");
  if (!attack || !control) fail(`--target needs a built-in direct PreToolUse Bash attack and Bash control: ${o.target}`);
  const prior = o.baseline ? readBaseline(o.baseline, o.target) : null;

  const root = realpathSync(env.FAILPROOFAI_PACK_DIR || join(env.FAILPROOFAI_HOME || join(homedir(), ".failproofai"), "policies", "packs"));
  const manifestBytes = readFileSync(join(root, "installed.json"));
  let installed;
  try { installed = JSON.parse(manifestBytes); } catch { fail("Installed manifest must be valid JSON"); }
  const matches = (installed?.packs ?? []).filter((p) => p.policies?.some((policy) => policy.name === o.target));
  if (matches.length !== 1) fail(`Exactly one installed pack must declare ${o.target}, found ${matches.length}`);
  const pack = matches[0];
  const source = realpathSync(resolve(root, pack.entry));
  if (!source.startsWith(root + sep)) fail("Artifact escapes the pack directory");
  const artifactBytes = readFileSync(source);
  if (hash(artifactBytes) !== pack.sha256) fail("Installed artifact failed its SHA-256 integrity check");
  const version = spawnSync(BIN, ["--version"], { encoding: "utf8", timeout: 15000, env }).stdout?.trim() || fail(`Engine version unavailable from ${BIN}`);

  const ctx = { target: o.target, pack, decl: pack.policies.find((p) => p.name === o.target), attack, control, artifactBytes };
  const faults = FAULTS.map((fault) => measure(fault, ctx));
  if (!readFileSync(join(root, "installed.json")).equals(manifestBytes) || !readFileSync(source).equals(artifactBytes))
    fail("Source pack changed during the measurement; discard it");

  const injected = faults.filter((f) => f.stage !== "control");
  const summary = { closed: injected.filter((f) => f.outcome === "CLOSED").length,
    open: injected.filter((f) => f.outcome === "OPEN" && !f.documentedOpen).length,
    documentedOpen: injected.filter((f) => f.outcome === "OPEN" && f.documentedOpen).length,
    errors: faults.filter((f) => f.outcome === "ERROR").length };
  const comparison = prior && { baseline: o.baseline,
    regressions: faults.filter((f) => prior.get(f.id) === "CLOSED" && f.outcome === "OPEN").map((f) => f.id),
    improvements: faults.filter((f) => prior.get(f.id) === "OPEN" && f.outcome === "CLOSED").map((f) => f.id),
    unbaselined: faults.filter((f) => !prior.has(f.id)).map((f) => f.id),
    removed: [...prior.keys()].filter((id) => !faults.some((f) => f.id === id)) };
  const invalid = summary.errors || faults.some((f) => f.stage === "control" && (f.attack !== "DENY" || f.control !== "ALLOW")) ||
    comparison?.unbaselined.length || comparison?.removed.length;
  const status = invalid ? 2 : (comparison ? comparison.regressions.length : summary.open) ? 1 : 0;

  writeFileSync(out, JSON.stringify({ schemaVersion: 1, kind: "fault-injection", generatedAt: new Date().toISOString(),
    engine: { binary: BIN, version }, target: o.target, attack: attack.id, control: control.id, faults, summary, comparison }, null, 2) + "\n",
  { flag: "wx", mode: 0o600 });
  console.log(`\nfailproof fault injection · engine ${version} · target ${o.target} · attack ${attack.id} · control ${control.id}\n`);
  for (const f of faults) console.log(`  ${f.outcome.padEnd(7)} ${f.stage.padEnd(8)} ${f.id.padEnd(24)} attack ${f.attack.padEnd(6)} control ${f.control}${f.documentedOpen ? "  (documented fail-open)" : ""}`);
  console.log(`\n${summary.closed} faults fail closed · ${summary.open} fail open · ${summary.documentedOpen} documented fail-open · ${summary.errors} errors`);
  if (comparison) console.log(`Compared with ${o.baseline}: ${comparison.regressions.length} regressions (${comparison.regressions.join(", ") || "none"}) · improvements: ${comparison.improvements.join(", ") || "none"}` +
    (comparison.unbaselined.length || comparison.removed.length ? ` · faults need review: ${[...comparison.unbaselined, ...comparison.removed].join(", ")}` : ""));
  if (status === 2) console.error("INVALID: an engine error, an unhealthy control, or an incomplete baseline makes this measurement unusable.");
  console.log(`wrote ${out}`);
  return status;
}

try { process.exitCode = main(); } catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 2;
}
