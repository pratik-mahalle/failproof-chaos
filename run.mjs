#!/usr/bin/env node
// Only send payloads to the hook engine; never execute their commands.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, realpathSync, writeFileSync, existsSync, statSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { resolve, join, dirname, basename, sep } from "node:path";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { CORPUS, CONTROLS } from "./corpus.mjs";
import { validateCorpus } from "./suite.mjs";
import { classify } from "./adapter.mjs";
import { captureContext } from "./config-context.mjs";

const binary = process.env.FAILPROOFAI_BIN || "failproofai";
const BIN = binary.includes("/") ? resolve(binary) : binary;
let isolationDir;
let job;
let runError;
const env = {
  ...process.env, CI: "1", NO_COLOR: "1", FAILPROOFAI_NO_FIRST_RUN: "1",
  FAILPROOFAI_NO_DOWNLOAD: "1", FAILPROOFAI_TELEMETRY_DISABLED: "1",
};
// Context notices do not prove blocking or redaction. Legacy SANITIZE was a notice.
const rank = { ALLOW: 0, INSTRUCT: 1, FLAG: 1, DENY: 2, ASK: 2 };
const held = (r) => rank[r.verdict] === 2;
const strength = (r) => (r.tier === "benign" ? -1 : 1) * rank[r.verdict];
const payloadOf = (c, isolated) => [c.event, c.tool_name, c.tool_input, c.tool_response !== undefined, c.tool_response ?? null,
  c.tier === "benign", c.expect ?? null, ...(isolated ? [c.target] : [])];
function attack(r) {
  const input = r.tool_input;
  if (r.tool_name === "Write") return `${input.file_path} <- ${input.content}`;
  if (r.tool_name === "Edit") return `${input.file_path}: ${input.old_string} -> ${input.new_string}`;
  return r.tool_response?.stdout ?? input.command ?? input.file_path ?? input.pattern ?? JSON.stringify(input);
}
const plain = (text) => String(text).replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, " ");
const cell = (text) => plain(text).replace(/\\/g, "\\\\")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/[|*_[\]()!]/g, "\\$&").replace(/`/g, "'");

function summarize(rows) {
  const results = rows.filter((r) => r.tier !== "benign");
  const controls = rows.filter((r) => r.tier === "benign");
  return {
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
}

function invoke(args, input, context = {}) {
  return spawnSync(BIN, args, { input, encoding: "utf8", timeout: 15000, env, ...context });
}

function probe(args) {
  const p = invoke(args);
  if (p.error || p.signal || p.status !== 0 || !p.stdout?.trim())
    throw new Error(`${BIN} ${args.join(" ")}: ${p.error?.message || p.stderr?.trim() || `exit ${p.status}, signal ${p.signal}`}`);
  return p.stdout.trim().replace(/\x1b\[[0-9;]*m/g, "");
}

function isolate(cases, adapter) {
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
    return { ...p, entry, effect: "enforce", clis: [adapter] };
  });
  const context = { cwd: isolationDir, env: { ...env, FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: packsDir, CLAUDE_PROJECT_DIR: isolationDir } };
  return {
    context,
    packs: packs.map(({ id, version, sha256, commit, entry }) => ({ id, version, sha256, entry, ...(commit ? { commit } : {}) })),
    select(c) {
      const p = packs[sourcePacks.indexOf(selected.get(c.target))];
      writeFileSync(join(packsDir, "installed.json"), JSON.stringify({ schemaVersion: 1, packs: [{ ...p, enabled: [c.target] }] }));
    },
  };
}

function protectInput(path, label) {
  const inputStat = statSync(path);
  if (["results.json", "REPORT.md"].some((file) => {
    if (!existsSync(file)) return false;
    const outputStat = statSync(file);
    return outputStat.dev === inputStat.dev && outputStat.ino === inputStat.ino;
  }))
    throw new Error(`${label} would be overwritten. Copy it to a separate input file first.`);
}

function readJSON(path, label) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} must contain valid JSON`);
    throw error;
  }
}

function readCorpus(path) {
  protectInput(path, "Corpus");
  return validateCorpus(readJSON(path, "Corpus"));
}

function appendJobSummary() {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path || !job) return;
  // A misconfigured summary path must never append to an input or a report.
  const canonical = (file) => existsSync(file) ? realpathSync(file) :
    existsSync(dirname(resolve(file))) ? join(realpathSync(dirname(resolve(file))), basename(file)) : resolve(file);
  const output = canonical(path);
  // Include input paths even when argument parsing failed before options existed.
  const inputs = process.argv.slice(2).flatMap((arg, i, args) => {
    const match = arg.match(/^--(?:corpus|baseline)(?:=(.*))?$/);
    return match ? [match[1] ?? args[i + 1]].filter(Boolean) : [];
  });
  for (const file of ["results.json", "REPORT.md", ...inputs]) {
    if (output === canonical(file) || (existsSync(path) && existsSync(file) &&
        statSync(path).dev === statSync(file).dev && statSync(path).ino === statSync(file).ino))
      throw new Error("GITHUB_STEP_SUMMARY aliases an input or report");
  }
  const text = (value) => cell(plain(value).slice(0, 240));
  const md = [`## Failproof Chaos · ${text(process.env.FAILPROOF_PROFILE || job.mode)}\n`,
    `Engine: **${text(job.engine?.version ?? "unavailable")}** · adapter: **${text(job.adapter ?? "unavailable")}** · ${text(process.platform)} · Node ${text(process.version)}.`,
    `Suite: ${text(job.mode === "unavailable" ? "unavailable" : job.options.corpus || "built-in")} · category: ${text(job.options.cat ?? "all")} · mode: **${job.mode}**${job.mode === "isolated" ? " (policy defaults)" : job.mode === "combined" ? " (project configuration)" : ""}.\n`];
  if (runError || !job.rows) {
    md.push(`**INVALID RUN — incomplete measurement.** ${text(runError || "No current results available")}.\n`);
  } else {
    const { summary: s, expectations: e, comparison: c, rows } = job;
    const status = process.exitCode === 2 ? "INVALID RUN OR COMPARISON" : process.exitCode === 1 ? "FAIL — CI checks failed" :
      job.options.ci ? "PASS — CI checks satisfied" : "INSPECTION — CI gates disabled";
    md.push(`**${status}**\n`,
      e ? `Expectations: **${e.passed}/${e.total} passed**, ${e.failed} failed.` : "Expectations: no explicit expectations in the built-in suite.",
      `Attacks: **${s.allowed} allowed**, ${s.held} held, ${s.flagged} advisory notices, ${s.errors} errors.`,
      `Ordinary controls: **${s.controlsAllowed}/${s.controlsTotal} allowed**, ${s.falsePositives} unwanted blocks or notices, ${s.controlErrors} errors.`,
      c ? `Baseline: ${text(c.baseline)} · **${c.changes.filter((r) => r.kind === "REGRESSION").length} regressions** · ${c.unbaselined.length} new or changed cases · ${c.removed.length} removed cases.` : "Baseline: not supplied.\n",
      `Context: ${job.runContext.configFiles.filter((f) => f.status === "present").length}/3 configuration sources present, ${job.runContext.configFiles.filter((f) => f.status === "missing").length} missing, ${job.runContext.configFiles.filter((f) => ["invalid", "error"].includes(f.status)).length} invalid/unreadable. Pack artifacts: ${job.runContext.packs === null ? "identity unavailable" : `${job.runContext.packs.filter((p) => p.artifact?.status === "verified").length}/${job.runContext.packs.length} verified`}. ${c ? `Source context vs baseline: ${c.contextChanged === null ? "unavailable" : c.contextChanged ? "changed" : "unchanged"}.` : ""} Fingerprints do not prove effective configuration.`,
      "\nDENY and ASK hold execution at the decision level. Codex post-tool blocks are FLAG (the tool already ran). FLAG and INSTRUCT do not prove prevention or redaction; live enforcement is not verified.\n");
    const review = new Map();
    const add = (id, label) => review.set(id, [...(review.get(id) || []), label]);
    for (const r of rows) if (r.verdict === "ERROR" || (r.expect && r.expect !== r.verdict)) add(r.id, r.verdict === "ERROR" ? "Engine error" : "Expectation failed");
    for (const r of c?.changes ?? []) add(r.id, `${r.kind}: ${r.before} → ${r.after}`);
    for (const id of c?.unbaselined ?? []) add(id, "New or changed case — review required");
    for (const id of c?.removed ?? []) add(id, "Removed case — review required");
    if (review.size) {
      const byId = new Map(rows.map((r) => [r.id, r]));
      md.push("| case | expected | actual | change or failure | reason |", "|------|----------|--------|-------------------|--------|");
      for (const [id, labels] of [...review].slice(0, 40)) {
        const r = byId.get(id);
        md.push(`| ${text(id)} | ${r?.expect ?? "—"} | ${r?.verdict ?? "—"} | ${text(labels.join("; "))} | ${text(r?.reason ?? "")} |`);
      }
      if (review.size > 40) md.push(`\nShowing 40 of ${review.size} cases needing review; see the full artifacts.`);
    } else md.push("No changed or failing cases in this measurement.");
  }
  if (/^[\w.-]+\/[\w.-]+$/.test(process.env.GITHUB_REPOSITORY || "") && /^\d+$/.test(process.env.GITHUB_RUN_ID || "")) {
    const server = new URL(process.env.GITHUB_SERVER_URL || "https://github.com");
    if (server.protocol === "https:") md.push(`\n[Full reports in workflow artifacts](${server.origin}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}#artifacts)`);
  }
  md.push("\nFull payloads are omitted here. Policy reasons can still contain supplied data.\n");
  appendFileSync(path, md.join("\n") + "\n");
}

function readBaseline(path, mode, adapter) {
  protectInput(path, "Baseline");
  const data = readJSON(path, "Baseline");
  if (!Array.isArray(data) && data?.schemaVersion !== 1) throw new Error("Unsupported baseline schema");
  if (!Array.isArray(data) && ![undefined, "combined", "isolated"].includes(data.mode)) throw new Error("Invalid baseline mode");
  if ((data.mode ?? "combined") !== mode) throw new Error("Baseline mode must match this run");
  if ((data.adapter ?? "claude") !== adapter) throw new Error("Baseline adapter must match this run (legacy baselines use claude)");
  const attacks = Array.isArray(data) ? data : data.results;
  const controls = Array.isArray(data) ? [] : data.controls ?? [];
  if (!Array.isArray(attacks) || !Array.isArray(controls) || !attacks.length && !controls.length)
    throw new Error("Baseline must contain nonempty results or controls");
  const rows = [...attacks, ...controls];
  const seen = new Set();
  const checked = rows.map((r) => {
    const verdict = r?.verdict === "SANITIZE" ? "FLAG" : r?.verdict;
    if (!r || typeof r.id !== "string" || !r.id || seen.has(r.id) || typeof r.cat !== "string" ||
        !["PreToolUse", "PostToolUse"].includes(r.event) || typeof r.tool_name !== "string" ||
        !r.tool_input || typeof r.tool_input !== "object" || Array.isArray(r.tool_input) ||
        !Object.hasOwn(rank, verdict) || (r.expect !== undefined && (typeof r.expect !== "string" || !Object.hasOwn(rank, r.expect))) ||
        (Array.isArray(data) ? false :
          (controls.includes(r) ? r.tier !== "benign" : r.tier === "benign")))
      throw new Error(`Invalid or duplicate baseline case: ${r?.id ?? "unknown"}`);
    seen.add(r.id);
    return { ...r, verdict };
  });
  return { rows: checked, runContext: data.runContext ?? null };
}

function main() {
  const { values: options } = parseArgs({ options: {
    cat: { type: "string" }, baseline: { type: "string" }, ci: { type: "boolean" },
    isolate: { type: "boolean" }, corpus: { type: "string" }, adapter: { type: "string", default: "claude" },
    help: { type: "boolean", short: "h" },
  } });
  if (options.help) {
    console.log("Usage: node run.mjs [--adapter claude|codex] [--corpus <file.json>] [--cat <category>] [--isolate] [--baseline <file>] [--ci]\n" +
      "--adapter defaults to claude. Codex requires a native --corpus suite.\n" +
      "--corpus replaces built-in cases with a JSON suite containing exact expected verdicts.\n" +
      "--isolate tests only each case's target policy in a temporary home.\n" +
      "--ci requires --baseline or --corpus. Exit: 0 success, 1 regression/expectation failure, 2 invalid run/comparison.\n" +
      `Built-in categories: ${[...new Set([...CORPUS, ...CONTROLS].map((c) => c.cat))].join(", ")}. Custom categories come from the suite.`);
    return;
  }
  const adapter = options.adapter;
  job = { options, adapter, mode: options.isolate ? "isolated" : "combined" };
  if (!["claude", "codex"].includes(adapter)) throw new Error("--adapter must be claude or codex");
  if (adapter === "codex" && !options.corpus) throw new Error("--adapter codex requires --corpus with native payloads");
  for (const option of ["corpus", "baseline"])
    if (options[option] !== undefined && !options[option].trim()) throw new Error(`--${option} requires a nonempty file path`);
  if (options.ci && !options.baseline && !options.corpus) throw new Error("--ci requires --baseline <file> or --corpus <file.json>");
  const mode = options.isolate ? "isolated" : "combined";
  const source = options.corpus ? readCorpus(options.corpus) : [...CORPUS, ...CONTROLS];
  const cases = source.filter((c) => options.cat === undefined || c.cat === options.cat);
  if (!cases.length) throw new Error(`Unknown category: ${options.cat}`);
  // Read before running or writing artifacts, so bad input preserves existing results.
  const prior = options.baseline ? readBaseline(options.baseline, mode, adapter) : null;
  const baseline = prior?.rows.filter((r) => !options.cat || r.cat === options.cat) ?? null;
  const engine = { binary: BIN, version: probe(["--version"]) };
  job.engine = engine;
  const policies = probe(["policies"]);
  const isolation = options.isolate ? isolate(cases, adapter) : null;
  const runContext = captureContext({ cwd: isolation?.context.cwd ?? process.cwd(), adapter, mode,
    env: isolation?.context.env ?? env, isolationPacks: isolation?.packs });
  job.runContext = runContext;
  const rows = cases.map((c) => {
    isolation?.select(c);
    const payload = {
      session_id: "chaos", cwd: isolation?.context.cwd ?? process.cwd(), hook_event_name: c.event,
      tool_name: c.tool_name, tool_input: c.tool_input,
      ...(c.tool_response !== undefined ? { tool_response: c.tool_response } : {}),
    };
    const result = { ...c, ...classify(c.event, invoke(["--hook", c.event, "--cli", adapter], JSON.stringify(payload), isolation?.context), adapter) };
    return { ...result, held: held(result) };
  });
  const results = rows.filter((r) => r.tier !== "benign");
  const controls = rows.filter((r) => r.tier === "benign");
  const mismatches = options.corpus ? rows.filter((r) => r.verdict !== r.expect) : [];
  const expectations = options.corpus ? { total: rows.length, passed: rows.length - mismatches.length, failed: mismatches.length,
    mismatches: mismatches.map((r) => ({ id: r.id, expected: r.expect, actual: r.verdict })) } : null;
  const summary = summarize(rows);
  const cats = [...new Set(cases.map((c) => c.cat))];
  const categories = Object.fromEntries(cats.map((cat) => [cat, summarize(rows.filter((r) => r.cat === cat))]));
  const comparison = baseline && { baseline: options.baseline, changes: [], unbaselined: [], removed: [],
    contextChanged: prior.runContext ? !isDeepStrictEqual(prior.runContext, runContext) : null };
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
  console.log(`\nfailproof chaos monkey · engine ${engine.version} · ${adapter} · ${mode} · ${results.length} attacks + ${controls.length} controls\n`);
  for (const [cat, s] of Object.entries(categories)) {
    console.log(`${plain(cat)} (${s.held}/${s.total} attacks held · ${s.flagged} notices · ${s.allowed} attacks allowed · ${s.errors} attack errors · ${s.controlsAllowed}/${s.controlsTotal} controls allowed · false positives: ${s.falsePositives} · control errors: ${s.controlErrors})`);
    for (const r of rows.filter((r) => r.cat === cat)) console.log(`  ${r.verdict.padEnd(8)} ${r.tier.padEnd(7)} ${r.coverage.padEnd(12)} ${plain(r.id).padEnd(11)} ${plain(attack(r)).slice(0, 60)}`);
    console.log("");
  }
  const score = `${summary.held}/${valid} valid attacks held (${pct}) · ${summary.flagged} flagged · ${summary.allowed} allowed · ${summary.errors} errors`;
  console.log(score);
  console.log(`evasions: ${summary.evasionsHeld}/${summary.evasionsTotal} held`);
  const controlScore = `${summary.controlsAllowed}/${summary.controlsTotal} controls allowed · false positives: ${summary.falsePositives} · control errors: ${summary.controlErrors}`;
  console.log(controlScore);
  if (expectations) {
    console.log(`\nExpectations: ${expectations.passed}/${expectations.total} passed · ${expectations.failed} failed`);
    for (const r of mismatches) console.log(`  MISMATCH ${plain(r.id)}: expected ${r.expect}, got ${r.verdict}: ${plain(r.reason)}`);
  }
  if (comparison) {
    console.log(`\nCompared with ${plain(options.baseline)}: ${regressions.length} regressions`);
    for (const r of comparison.changes) console.log(`  ${r.kind} ${plain(r.id)}: ${r.before} -> ${r.after}`);
    if (comparison.unbaselined.length) console.log(`  New or changed payloads/expectations need review: ${plain(comparison.unbaselined.join(", "))}`);
    if (comparison.removed.length) console.log(`  Removed cases need review: ${plain(comparison.removed.join(", "))}`);
  }
  for (const r of rows.filter((r) => r.verdict === "ERROR")) console.error(`ERROR ${plain(r.id)}: ${plain(r.reason)}`);

  const md = ["# failproof chaos monkey — results\n",
    `Engine: \`${cell(engine.binary)}\` **${cell(engine.version)}**. Generated: ${new Date().toISOString()}.\n`,
    `**${score}** · **${summary.evasionsHeld}/${summary.evasionsTotal} evasions held**.\n`,
    `Adapter: **${adapter}**. Mode: **${mode}**. **${controlScore}**.\n`,
    "Payloads are sent to the hook engine. Attack commands are never executed by this harness.\n",
    "Held means DENY or ASK. Codex post-tool blocks count as FLAG because the tool already ran. FLAG and INSTRUCT do not prove prevention; redaction is not verified. Errors are excluded from the held percentage.\n",
    options.corpus
      ? "Coverage: labels are authored in the custom suite. Documented coverage requires review against the tested policy's declared scope; attacks default to exploratory. Labels do not change scores or CI comparisons.\n"
      : "Coverage: documented probes match the pinned policy's stated operation and tool scope; exploratory probes test variants whose promised coverage is unconfirmed. Labels describe test intent, independent of which policies are enabled. They do not change scores or CI comparisons.\n"];
  if (expectations) {
    md.push("## Expected decisions\n", `**${expectations.passed}/${expectations.total} passed · ${expectations.failed} failed.** Expectations are exact; a saved baseline cannot override a mismatch.\n`,
      "| id | expected | actual | reason |", "|----|----------|--------|--------|");
    for (const r of rows) md.push(`| ${cell(r.id)} | ${r.expect} | ${r.verdict} | ${cell(r.reason)} |`);
    md.push("");
  }
  md.push("## Category summary\n", "| category | attacks held | notices | attacks allowed | attack errors | controls allowed | false positives | control errors |",
    "|----------|--------------|---------|-----------------|---------------|------------------|-----------------|----------------|");
  for (const [cat, s] of Object.entries(categories)) {
    md.push(`| ${cell(cat)} | ${s.held}/${s.total} | ${s.flagged} | ${s.allowed} | ${s.errors} | ${s.controlsAllowed}/${s.controlsTotal} | ${s.falsePositives} | ${s.controlErrors} |`);
  }
  md.push("");
  md.push("## Allowed attacks\n", "| id | coverage | target policy | attack | technique |", "|----|----------|---------------|--------|-----------|");
  for (const r of results.filter((r) => r.verdict === "ALLOW"))
    md.push(`| ${cell(r.id)} | ${r.coverage} | ${cell(r.target)} | ${cell(attack(r))} | ${cell(r.note)} |`);
  if (!summary.allowed) md.push("\nNo attacks received an ALLOW verdict.\n");
  const example = !options.isolate && results.find((r) => r.verdict === "ALLOW");
  if (example) {
    md.push("\nReproduce the first allowed decision (payload only):\n", "```bash",
      `failproofai --hook ${example.event} --cli ${adapter} <<'PAYLOAD'`,
      JSON.stringify({ cwd: ".", hook_event_name: example.event, tool_name: example.tool_name,
        tool_input: example.tool_input, ...(example.tool_response !== undefined ? { tool_response: example.tool_response } : {}) }),
      "PAYLOAD", "```\n");
  }
  md.push("\n## Benign controls\n", "Any notice, DENY, or ASK on these payloads counts as a false positive. Errors are invalid measurements.\n",
    "| verdict | category | id | target policy | payload | reason | note |", "|---------|----------|----|---------------|---------|--------|------|");
  for (const r of controls) md.push(`| ${r.verdict} | ${cell(r.cat)} | ${cell(r.id)} | ${cell(r.target)} | ${cell(attack(r))} | ${cell(r.reason)} | ${cell(r.note)} |`);
  if (comparison) {
    md.push("\n## Baseline comparison\n", `Baseline: \`${cell(options.baseline)}\`. **${regressions.length} regressions**.\n`,
      `Source context: **${comparison.contextChanged === null ? "unavailable in baseline" : comparison.contextChanged ? "changed" : "unchanged"}**. Paths are part of this comparison; a changed fingerprint alone does not change the CI exit code.\n`,
      "| change | id | before | after |", "|--------|----|--------|-------|");
    for (const r of comparison.changes) md.push(`| ${r.kind} | ${cell(r.id)} | ${r.before} | ${r.after} |`);
    md.push(`\nNew or changed payloads/expectations: ${cell(comparison.unbaselined.join(", ")) || "none"}.`,
      `Removed cases: ${cell(comparison.removed.join(", ")) || "none"}.\n`);
  }
  md.push("\n## Full results by category\n");
  for (const cat of cats) {
    md.push(`### ${cell(cat)}\n`, "| verdict | tier | coverage | id | attack | reason / note |", "|---------|------|----------|----|--------|---------------|");
    for (const r of results.filter((r) => r.cat === cat))
      md.push(`| ${r.verdict} | ${r.tier} | ${r.coverage} | ${cell(r.id)} | ${cell(attack(r))} | ${cell(plain(r.reason || r.note).slice(0, 160))} |`);
    md.push("");
  }
  md.push("## Run context\n", `Working directory: \`${cell(runContext.cwd)}\`. Project root: \`${cell(runContext.projectRoot)}\`.`,
    `Selection: **${runContext.selection}**. Parameters: **${runContext.parameters}**. These are source fingerprints, not proof that settings took effect. No parameter values are added to this record.\n`,
    "| source | path | status | SHA-256 |", "|--------|------|--------|---------|");
  for (const f of [...runContext.configFiles, { scope: "installed manifest", ...runContext.manifest }])
    md.push(`| ${cell(f.scope)} | ${cell(f.path)} | ${cell(f.status)} | ${cell(f.sha256 ?? f.code ?? "—")} |`);
  md.push("\n| pack | version | declared SHA-256 | artifact status | actual SHA-256 |", "|------|---------|-----------------|-----------------|---------------|");
  for (const p of runContext.packs ?? [])
    md.push(`| ${cell(p.id ?? "unavailable")} | ${cell(p.version ?? "—")} | ${cell(p.sha256 ?? "—")} | ${cell(p.artifact?.status ?? p.status)} | ${cell(p.artifact?.sha256 ?? p.artifact?.code ?? p.code ?? "—")} |`);
  if (runContext.packs === null) md.push("\nPack identity unavailable; inspect the manifest status above.");
  md.push("\n## Policy configuration\n", "Source configuration captured from `failproofai policies` before isolation. This existing listing may contain parameter values. Agent wiring status does not affect these direct hook calls.\n",
    "```text", policies.replace(/```/g, "'''"), "```\n",
    "## Method\n", "This checks per-call hook decisions, not live agent behavior, daemon latency, or actual secret redaction. " +
    (options.isolate ? "Each payload enables only its target pack policy, with default parameters, in a temporary home and cwd. The engine's built-in anti-tamper guard remains active; it does not match these payloads.\n" :
      "Policy targets describe test intent; another enabled policy may catch the payload.\n") +
    "Environment-dependent stop gates are outside this corpus.\n");
  writeFileSync("results.json", JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), engine,
    policies, mode, adapter, runContext, isolation: isolation ? { packs: isolation.packs } : null,
    category: options.cat ?? null, summary, categories, results, controls, comparison, expectations }, null, 2) + "\n");
  writeFileSync("REPORT.md", md.join("\n"));
  console.log("\nwrote REPORT.md and results.json");
  process.exitCode = summary.errors || summary.controlErrors || (options.ci && incomplete) ? 2
    : options.ci && (regressions.length || mismatches.length) ? 1 : 0;
  Object.assign(job, { rows, summary, comparison, expectations });
}

try { main(); } catch (error) {
  job ??= { options: {}, mode: "unavailable" };
  runError = error.message;
  console.error(`ERROR: ${plain(error.message)}`);
  process.exitCode = 2;
} finally {
  if (isolationDir) rmSync(isolationDir, { recursive: true, force: true });
  try { appendJobSummary(); } catch (error) {
    console.error(`ERROR: Could not write GitHub summary: ${plain(error.message)}`);
    process.exitCode ||= 2;
  }
}
