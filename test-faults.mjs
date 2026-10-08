// Fault-injection CLI check; the fake engine emulates fail-closed and fail-open packs. Commands never execute.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const work = realpathSync(mkdtempSync(join(tmpdir(), "failproof-faults-check-")));
const cli = fileURLToPath(new URL("./faults.mjs", import.meta.url));
const engine = join(work, "engine.mjs"), packs = join(work, "packs");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const run = (args, mode = "default") => spawnSync(process.execPath, [cli, ...args], { cwd: work, encoding: "utf8", timeout: 60000,
  env: { ...process.env, FAILPROOFAI_BIN: engine, FAILPROOFAI_PACK_DIR: packs, FAULT_MODE: mode } });
const report = (name) => JSON.parse(readFileSync(join(work, name), "utf8"));
const runtime = ["policy-throws", "policy-invalid-result", "policy-hangs", "policy-not-registered"];

try {
  mkdirSync(join(packs, "artifacts"), { recursive: true });
  const real = "// REAL ARTIFACT\n";
  writeFileSync(join(packs, "artifacts", "real.mjs"), real);
  writeFileSync(join(packs, "installed.json"), JSON.stringify({ schemaVersion: 1, packs: [{ id: "FailproofAI/policies", version: "test",
    entry: "artifacts/real.mjs", sha256: sha(real), policies: [{ name: "block-sudo", match: { events: ["PreToolUse"], toolNames: ["Bash"] } }] }] }));
  writeFileSync(engine, `#!${process.execPath}
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
if (process.argv[2] === '--version') { console.log('9.8.7'); process.exit(0); }
const mode = process.env.FAULT_MODE;
if (mode === 'crash') process.exit(1);
const input = JSON.parse(readFileSync(0, 'utf8'));
const attack = input.tool_input.command === 'sudo rm /var/log/syslog';
const deny = (reason) => { console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } })); process.exit(0); };
const closed = () => deny('Blocked because a policy pack this machine is configured to enforce is not running');
const dir = process.env.FAILPROOFAI_PACK_DIR;
if (!existsSync(dir + '/installed.json')) process.exit(0);
let m; try { m = JSON.parse(readFileSync(dir + '/installed.json', 'utf8')); } catch { closed(); }
if (!Array.isArray(m.packs)) closed();
const file = dir + '/' + m.packs[0].entry;
if (!existsSync(file)) closed();
const code = readFileSync(file);
if (createHash('sha256').update(code).digest('hex') !== m.packs[0].sha256) closed();
const text = code.toString();
if (text.includes('fault probe: load failure')) closed();
if (text.includes('REAL ARTIFACT') || text.includes('deny("fault probe")')) { if (attack && mode !== 'healthy-broken') deny('sudo blocked'); process.exit(0); }
if (mode === 'all-closed') closed();
process.exit(0);
`, { mode: 0o755 });
  const source = [readFileSync(join(packs, "installed.json")), readFileSync(join(packs, "artifacts", "real.mjs"))];

  const first = run(["--out", "first.json"]);
  assert.equal(first.status, 1, first.stderr);
  const r = report("first.json");
  assert.equal(r.kind, "fault-injection");
  assert.equal(r.target, "block-sudo");
  assert.equal(r.attack, "sudo-01");
  assert.equal(r.control, "ok-sudo-01");
  assert.equal(r.engine.version, "9.8.7");
  assert.deepEqual(Object.fromEntries(r.faults.map((f) => [f.id, f.outcome])), {
    "healthy": "CLOSED", "healthy-synthetic": "CLOSED", "manifest-unreadable": "CLOSED", "manifest-invalid": "CLOSED",
    "artifact-hash-mismatch": "CLOSED", "artifact-missing": "CLOSED", "artifact-load-throws": "CLOSED", "artifact-load-timeout": "CLOSED",
    "policy-throws": "OPEN", "policy-invalid-result": "OPEN", "policy-hangs": "OPEN", "policy-not-registered": "OPEN", "manifest-absent": "OPEN" });
  assert.equal(r.faults.find((f) => f.id === "manifest-unreadable").attack, "DENY"); // fail-closed deny, not ERROR
  assert.equal(r.faults.find((f) => f.id === "healthy").control, "ALLOW");
  assert.equal(r.faults.find((f) => f.id === "manifest-absent").documentedOpen, true);
  assert.deepEqual(r.summary, { closed: 6, open: 4, documentedOpen: 1, errors: 0 });
  assert.equal(r.comparison, null);
  assert.deepEqual([readFileSync(join(packs, "installed.json")), readFileSync(join(packs, "artifacts", "real.mjs"))], source);

  // Only the documented fail-open remains: pass.
  assert.equal(run(["--out", "closed.json"], "all-closed").status, 0);
  // Same outcomes as the baseline: pass, even though faults are open.
  assert.equal(run(["--out", "same.json", "--baseline", "first.json"]).status, 0);
  assert.deepEqual(report("same.json").comparison.regressions, []);
  // CLOSED -> OPEN is a regression.
  assert.equal(run(["--out", "regressed.json", "--baseline", "closed.json"]).status, 1);
  assert.deepEqual(report("regressed.json").comparison.regressions, runtime);
  // OPEN -> CLOSED is reported and passes.
  assert.equal(run(["--out", "improved.json", "--baseline", "first.json"], "all-closed").status, 0);
  assert.deepEqual(report("improved.json").comparison.improvements, runtime);

  // Invalid measurements and inputs exit 2.
  assert.equal(run(["--out", "broken.json"], "healthy-broken").status, 2);
  assert.equal(report("broken.json").faults.find((f) => f.id === "healthy").attack, "ALLOW");
  assert.equal(run(["--out", "crash.json"], "crash").status, 2);
  assert.equal(run(["--out", "first.json"]).status, 2);
  assert.equal(run([]).status, 2);
  assert.equal(run(["--out", "x.json", "--target", "block-nothing"]).status, 2);
  const partial = report("first.json"); partial.faults.pop();
  writeFileSync(join(work, "partial.json"), JSON.stringify(partial));
  const incomplete = run(["--out", "incomplete.json", "--baseline", "partial.json"]);
  assert.equal(incomplete.status, 2);
  assert.deepEqual(report("incomplete.json").comparison.unbaselined, ["manifest-absent"]);
  writeFileSync(join(work, "other-target.json"), JSON.stringify({ ...r, target: "block-env-files" }));
  assert.equal(run(["--out", "y.json", "--baseline", "other-target.json"]).status, 2);
  console.log("Fault checks passed: fail-closed decoding, fail-open detection, baselines, invalid measurements, and source preservation.");
} finally {
  rmSync(work, { recursive: true, force: true });
}
