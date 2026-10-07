#!/usr/bin/env node
// Draft fixture data only: never invoke the engine or execute a captured tool call.
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { validateCorpus } from "./suite.mjs";

function main() {
  const { values: options } = parseArgs({ options: {
    input: { type: "string" }, id: { type: "string" }, cat: { type: "string" }, target: { type: "string" },
    tier: { type: "string" }, expect: { type: "string" }, out: { type: "string" },
    coverage: { type: "string" }, note: { type: "string" }, help: { type: "boolean", short: "h" },
  } });
  if (options.help) {
    console.log("Usage: node case.mjs --input <payload.json> --id <id> --cat <category> --target <policy>\n" +
      "  --tier <direct|evasion|benign> --expect <ALLOW|DENY|ASK|FLAG|INSTRUCT> --out <new-suite.json>\n" +
      "  [--coverage <documented|exploratory|benign>] [--note <source or explanation>]\n\n" +
      "Input: Claude-compatible hook_event_name (PreToolUse or PostToolUse), tool_name, tool_input,\n" +
      "and optional tool_response. Capture metadata cwd, session_id, transcript_path, permission_mode,\n" +
      "and tool_use_id is omitted with a notice; other fields are rejected.\n" +
      "Writes one schema-1 draft case to a new file. Benign cases require ALLOW.\n" +
      "Coverage defaults to exploratory for attacks and benign for controls.\n" +
      "Review/redact the draft and supply an ordinary ALLOW counterpart yourself. Reports include fixture data.\n" +
      "Replay uses the runner's cwd and does not restore session state. No tool call or engine is executed.\n" +
      "Exit: 0 draft created/help, 2 invalid input or write failure.");
    return;
  }
  for (const name of ["input", "id", "cat", "target", "tier", "expect", "out"])
    if (typeof options[name] !== "string" || !options[name].trim()) throw new Error(`--${name} requires a nonempty value`);
  const raw = readFileSync(options.input, "utf8");
  let payload;
  try { payload = JSON.parse(raw); } catch { throw new Error("Input payload must contain valid JSON"); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Input payload must be an object");
  const metadata = ["cwd", "session_id", "transcript_path", "permission_mode", "tool_use_id"];
  const supported = ["hook_event_name", "tool_name", "tool_input", "tool_response", ...metadata];
  const unknown = Object.keys(payload).find((key) => !supported.includes(key));
  if (unknown !== undefined) throw new Error(`Input payload field ${JSON.stringify(unknown)} is unsupported`);
  const cases = validateCorpus({ schemaVersion: 1, cases: [{
    id: options.id, cat: options.cat, target: options.target, tier: options.tier,
    event: payload.hook_event_name, tool_name: payload.tool_name, tool_input: payload.tool_input,
    ...(Object.hasOwn(payload, "tool_response") ? { tool_response: payload.tool_response } : {}),
    expect: options.expect,
    ...(options.coverage !== undefined ? { coverage: options.coverage } : {}),
    ...(options.note !== undefined ? { note: options.note } : {}),
  }] });
  // Exclusive creation also refuses symlink and hard-link aliases, including the input.
  writeFileSync(options.out, JSON.stringify({ schemaVersion: 1, cases }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  const omitted = metadata.filter((key) => Object.hasOwn(payload, key));
  if (omitted.length) console.error(`Omitted capture metadata: ${omitted.join(", ")}.`);
  console.error("Review/redact the draft before committing; fixture payloads and policy reasons appear in reports. Verify substitutions still reproduce the condition.");
  console.error("Replay uses the runner's cwd and does not restore session state. Supply and review an ordinary ALLOW counterpart separately.");
  console.log(`Created draft: ${JSON.stringify(options.out)}`);
}

try { main(); } catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 2;
}
