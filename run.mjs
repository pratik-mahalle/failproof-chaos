#!/usr/bin/env node
// Only send payloads to the hook engine; never execute their commands.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync, existsSync, statSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { resolve, join, dirname, sep } from "node:path";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { CORPUS, CONTROLS } from "./corpus.mjs";

const binary = process.env.FAILPROOFAI_BIN || "failproofai";
const BIN = binary.includes("/") ? resolve(binary) : binary;
let isolationDir;
const env = {
  ...process.env, CI: "1", NO_COLOR: "1", FAILPROOFAI_NO_FIRST_RUN: "1",
  FAILPROOFAI_NO_DOWNLOAD: "1", FAILPROOFAI_TELEMETRY_DISABLED: "1",
};
// Context notices do not prove blocking or redaction. Legacy SANITIZE was a notice.
const rank = { ALLOW: 0, INSTRUCT: 1, FLAG: 1, DENY: 2, ASK: 2 };
const held = (r) => rank[r.verdict] === 2;
const strength = (r) => (r.tier === "benign" ? -1 : 1) * rank[r.verdict];
const payloadOf = (c, isolated) => [c.event, c.tool_name, c.tool_input, c.tool_response ?? null,
  c.tier === "benign", ...(isolated ? [c.target] : [])];
const attack = (r) => r.tool_response?.stdout ?? r.tool_input.command ?? r.tool_input.file_path ?? r.tool_input.pattern ?? "";
const cell = (text) => String(text).replace(/\|/g, "\\|").replace(/`/g, "'").replace(/[\r\n]+/g, " ");

function invoke(args, input, context = {}) {
  return spawnSync(BIN, args, { input, encoding: "utf8", timeout: 15000, env, ...context });
}

function probe(args) {
  const p = invoke(args);
  if (p.error || p.signal || p.status !== 0 || !p.stdout?.trim())
    throw new Error(`${BIN} ${args.join(" ")}: ${p.error?.message || p.stderr?.trim() || `exit ${p.status}, signal ${p.signal}`}`);
  return p.stdout.trim().replace(/\x1b\[[0-9;]*m/g, "");
}

function isolate(cases) {
  const root = realpathSync(env.FAILPROOFAI_PACK_DIR || join(env.FAILPROOFAI_HOME || join(homedir(), ".failproofai"), "policies", "packs"));
  const manifest = JSON.parse(readFileSync(join(root, "installed.json"), "utf8"));
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.packs)) throw new Error("Unsupported installed policy manifest");
  const selected = new Map();
  for (const target of new Set(cases.map((c) => c.target))) {
    const matches = manifest.packs.filter((p) => p.policies?.some((policy) => policy.name === target));
    if (matches.length !== 1) throw new Error(`Isolation requires exactly one installed pack for ${target}, found ${matches.length}`);
    selected.set(target, matches[0]);
  }
  isolationDir = realpathSync(mkdtempSync(join(tmpdir(), "failproof-isolated-")));
  const home = join(isolationDir, ".failproofai");
  const packsDir = join(home, "policies", "packs");
  mkdirSync(packsDir, { recursive: true }); // The home is also the project marker.
  const sourcePacks = [...new Set(selected.values())];
  const packs = sourcePacks.map((p, i) => {
    if (typeof p.entry !== "string") throw new Error(`Missing artifact for ${p.id}`);
    const source = realpathSync(resolve(root, p.entry));
    if (!source.startsWith(root + sep)) throw new Error(`Artifact escapes pack directory: ${p.id}`);
    const contents = readFileSync(source);
    if (createHash("sha256").update(contents).digest("hex") !== p.sha256) throw new Error(`Policy integrity check failed: ${p.id}`);
    const entry = `artifacts/${i}.mjs`;
    mkdirSync(dirname(join(packsDir, entry)), { recursive: true });
    writeFileSync(join(packsDir, entry), contents);
    return { ...p, entry, effect: "enforce", clis: ["claude"] };
  });
  const context = { cwd: isolationDir, env: { ...env, FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: packsDir, CLAUDE_PROJECT_DIR: isolationDir } };
  return {
    context,
    packs: packs.map(({ id, version, sha256, commit }) => ({ id, version, sha256, ...(commit ? { commit } : {}) })),
    select(c) {
      const p = packs[sourcePacks.indexOf(selected.get(c.target))];
      writeFileSync(join(packsDir, "installed.json"), JSON.stringify({ schemaVersion: 1, packs: [{ ...p, enabled: [c.target] }] }));
    },
  };
}

function classify(event, p) {
  const error = (reason) => ({ verdict: "ERROR", reason });
  if (p.error || p.signal)
    return error(p.error?.message || `terminated by ${p.signal}`);
  // ponytail: known failure messages distinguish engine errors from policy catches;
  // use structured errors when failproofai exposes them.
  if (/could not evaluate this call|failproofaid could not be reached|different protocol version|policy pack this machine is configured to enforce is not running/.test(`${p.stdout}\n${p.stderr}`))
    return error((p.stderr || p.stdout).trim());
  if (p.status === 2) return { verdict: "DENY", reason: p.stderr?.trim() || "hook exited 2 (blocking decision)" };
  if (p.status !== 0) return error(`engine exited ${p.status}: ${p.stderr?.trim() || "no diagnostic"}`);
  const text = p.stdout?.trim();
  if (!text) return { verdict: "ALLOW", reason: "no decision emitted" };
  let out;
  try { out = JSON.parse(text); } catch { return error("invalid JSON from engine"); }
  if (!out || typeof out !== "object" || Array.isArray(out)) return error("invalid hook response");
  const hso = out.hookSpecificOutput ?? {};
  if (!hso || typeof hso !== "object" || Array.isArray(hso)) return error("invalid hookSpecificOutput");
  const decision = hso.permissionDecision ?? out.decision;
  const ctx = hso.additionalContext ?? "";
  const reason = hso.permissionDecisionReason ?? out.reason ?? "";
  if (typeof ctx !== "string" || typeof reason !== "string") return error("invalid hook context or reason");
  if (decision !== undefined && !["deny", "block", "ask", "allow", "approve"].includes(decision))
    return error(`unknown hook decision: ${String(decision)}`);
  if (decision === "deny" || decision === "block") return { verdict: "DENY", reason };
  if (decision === "ask") return { verdict: "ASK", reason };
  if (ctx.trim()) return { verdict: event === "PostToolUse" ? "FLAG" : "INSTRUCT", reason: ctx.trim() };
  if (decision !== undefined) return { verdict: "ALLOW", reason: reason || "permissive decision" };
  return error("response contains no recognized decision or context");
}

function readBaseline(path, mode) {
  const baselineStat = statSync(path);
  if (["results.json", "REPORT.md"].some((file) => {
    if (!existsSync(file)) return false;
    const outputStat = statSync(file);
    return outputStat.dev === baselineStat.dev && outputStat.ino === baselineStat.ino;
  }))
    throw new Error("Baseline would be overwritten. Copy it to a separate baseline file first.");
  const data = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(data) && data?.schemaVersion !== 1) throw new Error("Unsupported baseline schema");
  if (!Array.isArray(data) && ![undefined, "combined", "isolated"].includes(data.mode)) throw new Error("Invalid baseline mode");
  if ((data.mode ?? "combined") !== mode) throw new Error("Baseline mode must match this run");
  const attacks = Array.isArray(data) ? data : data.results;
  const controls = Array.isArray(data) ? [] : data.controls ?? [];
  if (!Array.isArray(attacks) || !attacks.length || !Array.isArray(controls)) throw new Error("Baseline must contain results and a valid controls array");
  const rows = [...attacks, ...controls];
  const seen = new Set();
  return rows.map((r) => {
    const verdict = r?.verdict === "SANITIZE" ? "FLAG" : r?.verdict;
    if (!r || typeof r.id !== "string" || !r.id || seen.has(r.id) || typeof r.cat !== "string" ||
        !["PreToolUse", "PostToolUse"].includes(r.event) || typeof r.tool_name !== "string" ||
        !r.tool_input || typeof r.tool_input !== "object" || Array.isArray(r.tool_input) ||
        !Object.hasOwn(rank, verdict) || (Array.isArray(data) ? false :
          (controls.includes(r) ? r.tier !== "benign" : r.tier === "benign")))
      throw new Error(`Invalid or duplicate baseline case: ${r?.id ?? "unknown"}`);
    seen.add(r.id);
    return { ...r, verdict };
  });
}

function main() {
  const { values: options } = parseArgs({ options: {
    cat: { type: "string" }, baseline: { type: "string" }, ci: { type: "boolean" },
    isolate: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  } });
  if (options.help) {
    console.log("Usage: node run.mjs [--cat <category>] [--isolate] [--baseline <file>] [--ci]\n" +
      "--isolate tests only each case's target policy in a temporary home.\n" +
      "--ci requires --baseline. Exit: 0 success, 1 regression, 2 invalid run/comparison.\n" +
      `Categories: ${[...new Set(CORPUS.map((c) => c.cat))].join(", ")}`);
    return;
  }
  if (options.ci && !options.baseline) throw new Error("--ci requires --baseline <file>");
  const mode = options.isolate ? "isolated" : "combined";
  const cases = [...CORPUS, ...CONTROLS].filter((c) => options.cat === undefined || c.cat === options.cat);
  if (!cases.length) throw new Error(`Unknown category: ${options.cat}`);
  // Read before running or writing artifacts, so bad input preserves existing results.
  const baseline = options.baseline ? readBaseline(options.baseline, mode).filter((r) => !options.cat || r.cat === options.cat) : null;
  const engine = { binary: BIN, version: probe(["--version"]) };
  const policies = probe(["policies"]);
  const isolation = options.isolate ? isolate(cases) : null;
  const rows = cases.map((c) => {
    isolation?.select(c);
    const payload = {
      session_id: "chaos", cwd: isolation?.context.cwd ?? process.cwd(), hook_event_name: c.event,
      tool_name: c.tool_name, tool_input: c.tool_input,
      ...(c.tool_response ? { tool_response: c.tool_response } : {}),
    };
    const result = { ...c, ...classify(c.event, invoke(["--hook", c.event, "--cli", "claude"], JSON.stringify(payload), isolation?.context)) };
    return { ...result, held: held(result) };
  });
  const results = rows.filter((r) => r.tier !== "benign");
  const controls = rows.filter((r) => r.tier === "benign");
  const summary = {
    total: results.length,
    held: results.filter(held).length,
    flagged: results.filter((r) => ["FLAG", "INSTRUCT"].includes(r.verdict)).length,
    allowed: results.filter((r) => r.verdict === "ALLOW").length,
    errors: results.filter((r) => r.verdict === "ERROR").length,
    evasionsHeld: results.filter((r) => r.tier === "evasion" && held(r)).length,
    evasionsTotal: results.filter((r) => r.tier === "evasion").length,
    controlsTotal: controls.length,
    controlsAllowed: controls.filter((r) => r.verdict === "ALLOW").length,
    falsePositives: controls.filter((r) => r.verdict !== "ALLOW" && r.verdict !== "ERROR").length,
    controlErrors: controls.filter((r) => r.verdict === "ERROR").length,
  };
  const comparison = baseline && { baseline: options.baseline, changes: [], unbaselined: [], removed: [] };
  if (comparison) {
    const previous = new Map(baseline.map((r) => [r.id, r]));
    for (const r of rows) {
      const before = previous.get(r.id);
      if (!before || !isDeepStrictEqual(payloadOf(before, options.isolate), payloadOf(r, options.isolate))) {
        comparison.unbaselined.push(r.id);
      } else if (r.verdict !== "ERROR" && r.verdict !== before.verdict) {
        comparison.changes.push({ id: r.id, before: before.verdict, after: r.verdict,
          kind: strength(r) < strength(before) ? "REGRESSION" : strength(r) > strength(before) ? "IMPROVEMENT" : "CHANGE" });
      }
      previous.delete(r.id);
    }
    comparison.removed = [...previous.keys()];
  }
  const regressions = comparison?.changes.filter((r) => r.kind === "REGRESSION") ?? [];
  const incomplete = comparison && (comparison.unbaselined.length || comparison.removed.length);
  const valid = summary.total - summary.errors;
  const pct = valid ? `${((summary.held / valid) * 100).toFixed(0)}%` : "n/a";
  const cats = [...new Set(cases.map((c) => c.cat))];
  console.log(`\nfailproof chaos monkey · engine ${engine.version} · ${mode} · ${results.length} attacks + ${controls.length} controls\n`);
  for (const cat of cats) {
    const rows = results.filter((r) => r.cat === cat);
    console.log(`${cat} (${rows.filter(held).length}/${rows.length} held)`);
    for (const r of rows) console.log(`  ${r.verdict.padEnd(8)} ${r.tier.padEnd(7)} ${r.id.padEnd(9)} ${attack(r).slice(0, 60)}`);
    console.log("");
  }
  const score = `${summary.held}/${valid} valid attacks held (${pct}) · ${summary.flagged} flagged · ${summary.allowed} allowed · ${summary.errors} errors`;
  console.log(score);
  console.log(`evasions: ${summary.evasionsHeld}/${summary.evasionsTotal} held`);
  const controlScore = `${summary.controlsAllowed}/${summary.controlsTotal} controls allowed · ${summary.falsePositives} false positives · ${summary.controlErrors} control errors`;
  console.log(controlScore);
  if (comparison) {
    console.log(`\nCompared with ${options.baseline}: ${regressions.length} regressions`);
    for (const r of comparison.changes) console.log(`  ${r.kind} ${r.id}: ${r.before} -> ${r.after}`);
    if (comparison.unbaselined.length) console.log(`  New or changed payloads need review: ${comparison.unbaselined.join(", ")}`);
    if (comparison.removed.length) console.log(`  Removed cases need review: ${comparison.removed.join(", ")}`);
  }
  for (const r of rows.filter((r) => r.verdict === "ERROR")) console.error(`ERROR ${r.id}: ${r.reason}`);

  const md = ["# failproof chaos monkey — results\n",
    `Engine: \`${cell(engine.binary)}\` **${cell(engine.version)}**. Generated: ${new Date().toISOString()}.\n`,
    `**${score}** · **${summary.evasionsHeld}/${summary.evasionsTotal} evasions held**.\n`,
    `Mode: **${mode}**. **${controlScore}**.\n`,
    "Payloads are sent to the hook engine. Attack commands are never executed by this harness.\n",
    "Held means DENY or ASK. FLAG and INSTRUCT are notices; redaction is not verified. Errors are excluded from the held percentage.\n"];
  md.push("## Allowed attacks\n", "| id | target policy | attack | technique |", "|----|---------------|--------|-----------|");
  for (const r of results.filter((r) => r.verdict === "ALLOW"))
    md.push(`| ${r.id} | ${cell(r.target)} | ${cell(attack(r))} | ${cell(r.note)} |`);
  if (!summary.allowed) md.push("\nNo attacks received an ALLOW verdict.\n");
  const example = !options.isolate && results.find((r) => r.verdict === "ALLOW");
  if (example) {
    md.push("\nReproduce the first allowed decision (payload only):\n", "```bash",
      `failproofai --hook ${example.event} <<'PAYLOAD'`,
      JSON.stringify({ cwd: ".", hook_event_name: example.event, tool_name: example.tool_name,
        tool_input: example.tool_input, ...(example.tool_response ? { tool_response: example.tool_response } : {}) }),
      "PAYLOAD", "```\n");
  }
  md.push("\n## Benign controls\n", "Any notice, DENY, or ASK on these payloads counts as a false positive. Errors are invalid measurements.\n",
    "| verdict | id | target policy | payload | note |", "|---------|----|---------------|---------|------|");
  for (const r of controls) md.push(`| ${r.verdict} | ${r.id} | ${cell(r.target)} | ${cell(attack(r))} | ${cell(r.reason || r.note)} |`);
  if (comparison) {
    md.push("\n## Baseline comparison\n", `Baseline: \`${cell(options.baseline)}\`. **${regressions.length} regressions**.\n`,
      "| change | id | before | after |", "|--------|----|--------|-------|");
    for (const r of comparison.changes) md.push(`| ${r.kind} | ${r.id} | ${r.before} | ${r.after} |`);
    md.push(`\nNew or changed payloads: ${comparison.unbaselined.join(", ") || "none"}.`,
      `Removed cases: ${comparison.removed.join(", ") || "none"}.\n`);
  }
  md.push("\n## Full results by category\n");
  for (const cat of cats) {
    md.push(`### ${cat}\n`, "| verdict | tier | id | attack | reason / note |", "|---------|------|----|--------|---------------|");
    for (const r of results.filter((r) => r.cat === cat))
      md.push(`| ${r.verdict} | ${r.tier} | ${r.id} | ${cell(attack(r))} | ${cell(r.reason || r.note).slice(0, 160)} |`);
    md.push("");
  }
  md.push("## Policy configuration\n", "Source configuration captured from `failproofai policies`. Agent wiring status does not affect these direct hook calls.\n",
    "```text", policies.replace(/```/g, "'''"), "```\n",
    "## Method\n", "This checks per-call hook decisions, not live agent behavior, daemon latency, or actual secret redaction. " +
    (options.isolate ? "Each payload enables only its target pack policy, with default parameters, in a temporary home and cwd. The engine's built-in anti-tamper guard remains active; it does not match these payloads.\n" :
      "Policy targets describe test intent; another enabled policy may catch the payload.\n") +
    "Environment-dependent stop gates are outside this corpus.\n");
  writeFileSync("results.json", JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), engine,
    policies, mode, isolation: isolation ? { packs: isolation.packs } : null,
    category: options.cat ?? null, summary, results, controls, comparison }, null, 2) + "\n");
  writeFileSync("REPORT.md", md.join("\n"));
  console.log("\nwrote REPORT.md and results.json");
  process.exitCode = summary.errors || summary.controlErrors || (options.ci && incomplete) ? 2 : options.ci && regressions.length ? 1 : 0;
}

try { main(); } catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 2;
} finally {
  if (isolationDir) rmSync(isolationDir, { recursive: true, force: true });
}
