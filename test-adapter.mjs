import assert from "node:assert/strict";
import { classify } from "./adapter.mjs";

const processResult = (output, overrides = {}) => ({ status: 0, stdout: output === undefined ? "" : JSON.stringify(output), stderr: "", ...overrides });
const verdict = (event, output, expected, overrides = {}) => {
  const result = classify(event, processResult(output, overrides), "codex");
  assert.equal(result.verdict, expected, `${event}: ${JSON.stringify(output)} -> ${JSON.stringify(result)}`);
  return result;
};
const pre = "PreToolUse";
const post = "PostToolUse";
const deny = { hookSpecificOutput: { hookEventName: pre, permissionDecision: "deny", permissionDecisionReason: "blocked" } };

verdict(pre, undefined, "ALLOW");
verdict(post, undefined, "ALLOW");
assert.equal(verdict(pre, deny, "DENY").reason, "blocked");
verdict(pre, { decision: "block", reason: "blocked", hookSpecificOutput: { additionalContext: "advice" } }, "DENY");
verdict(pre, { hookSpecificOutput: { permissionDecision: "allow" } }, "ALLOW");
verdict(pre, { hookSpecificOutput: { permissionDecision: "allow", additionalContext: "advice" } }, "INSTRUCT");
verdict(pre, { hookSpecificOutput: { additionalContext: "advice" } }, "INSTRUCT");
verdict(post, { hookSpecificOutput: { hookEventName: post, additionalContext: "advice" } }, "FLAG");
assert.match(verdict(post, { decision: "block", reason: "secret output" }, "FLAG").reason, /tool already ran.*secret output/);
verdict(post, { continue: false, stopReason: "review output" }, "FLAG");
verdict(post, { continue: true }, "ALLOW");
verdict(pre, undefined, "DENY", { status: 2, stderr: "blocked" });
assert.match(verdict(post, undefined, "FLAG", { status: 2, stderr: "blocked" }).reason, /tool already ran/);

// Validate every field before accepting a blocking or permissive decision.
for (const output of [
  null, false, [], {}, { hookSpecificOutput: null },
  { hookSpecificOutput: { permissionDecision: "ask" } },
  { decision: "approve" }, { decision: "allow" }, { decision: "deny" },
  { decision: "block" }, { decision: "block", reason: " " },
  { ...deny, systemMessage: null }, { ...deny, continue: false },
  { ...deny, stopReason: "stop" }, { ...deny, suppressOutput: false },
  { ...deny, updatedInput: { command: "safe" } },
  { decision: "block", reason: "blocked", hookSpecificOutput: { permissionDecision: "allow" } },
  { hookSpecificOutput: { permissionDecision: "deny", updatedInput: { command: "safe" } } },
  { hookSpecificOutput: { permissionDecision: "allow", updatedInput: { command: "safe" } } },
  { hookSpecificOutput: { ...deny.hookSpecificOutput, additionalContext: null } },
  { hookSpecificOutput: { ...deny.hookSpecificOutput, permissionDecisionReason: 42 } },
  { hookSpecificOutput: { ...deny.hookSpecificOutput, hookEventName: post } },
  { hookSpecificOutput: { permissionDecision: "deny", unknown: true } },
  { systemMessage: "UI warning only" },
]) verdict(pre, output, "ERROR");

for (const output of [
  deny, { hookSpecificOutput: { permissionDecision: "deny" } },
  { decision: "block", reason: "blocked", suppressOutput: true },
  { decision: "block", reason: "blocked", updatedMCPToolOutput: "replacement" },
  { hookSpecificOutput: { additionalContext: "advice", updatedMCPToolOutput: "replacement" } },
  { continue: "false" }, { continue: false, stopReason: null },
  { continue: false, decision: "approve" },
]) verdict(post, output, "ERROR");

for (const event of [pre, post]) {
  verdict(event, undefined, "ERROR", { error: new Error("spawn failed"), status: null });
  verdict(event, undefined, "ERROR", { signal: "SIGTERM", status: null });
  verdict(event, undefined, "ERROR", { status: 1, stderr: "engine crash" });
  verdict(event, undefined, "ERROR", { stdout: "not JSON" });
  for (const reason of ["could not evaluate this call", "failproofaid could not be reached", "different protocol version",
    "policy pack this machine is configured to enforce is not running"])
    verdict(event, undefined, "ERROR", { status: 2, stderr: reason });
}
assert.equal(classify("PermissionRequest", processResult(deny), "codex").verdict, "ERROR");
assert.equal(classify(pre, processResult(deny), "other").verdict, "ERROR");

// Existing Claude decisions retain their meanings and default adapter.
assert.deepEqual(classify(pre, processResult(deny)), { verdict: "DENY", reason: "blocked" });
assert.equal(classify(pre, processResult({ hookSpecificOutput: { permissionDecision: "ask" } })).verdict, "ASK");
assert.equal(classify(post, processResult({ decision: "block", reason: "blocked" }), "claude").verdict, "DENY");
assert.equal(classify(post, processResult(undefined, { status: 2 })).verdict, "DENY");
console.log("Adapter response checks passed");
