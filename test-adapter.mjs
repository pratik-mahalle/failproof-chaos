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
verdict(pre, { decision: "block", reason: "blocked" }, "DENY");
verdict(pre, { decision: "block", reason: "blocked", hookSpecificOutput: { hookEventName: pre, additionalContext: "advice" } }, "DENY");
verdict(pre, { ...deny, reason: "legacy field ignored when the valid hook-specific decision is present" }, "DENY");
verdict(pre, { hookSpecificOutput: { hookEventName: pre, additionalContext: "advice" } }, "INSTRUCT");
verdict(post, { hookSpecificOutput: { hookEventName: post, additionalContext: "advice" } }, "FLAG");
assert.match(verdict(post, { decision: "block", reason: "secret output" }, "FLAG").reason, /tool already ran.*secret output/);
verdict(post, { continue: false, stopReason: "review output" }, "FLAG");
verdict(post, { continue: false, reason: "review output" }, "FLAG");
verdict(post, { continue: true }, "ALLOW");
verdict(pre, undefined, "DENY", { status: 2, stderr: "blocked" });
assert.match(verdict(post, undefined, "FLAG", { status: 2, stderr: "blocked" }).reason, /tool already ran/);

// Validate every field before accepting a blocking or permissive decision.
for (const output of [
  null, false, [], {}, { hookSpecificOutput: null },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "ask" } },
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
  { hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: "blocked" } },
  { hookSpecificOutput: { hookEventName: null, permissionDecision: "deny", permissionDecisionReason: "blocked" } },
  { hookSpecificOutput: { hookEventName: " ", permissionDecision: "deny", permissionDecisionReason: "blocked" } },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "deny" } },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "deny", permissionDecisionReason: null } },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "deny", permissionDecisionReason: " \n\t" } },
  { decision: "block", reason: "no fallback", hookSpecificOutput: { hookEventName: pre, permissionDecision: "deny" } },
  { decision: "block", reason: "blocked", hookSpecificOutput: {} },
  { decision: "block", reason: "blocked", hookSpecificOutput: { hookEventName: pre, permissionDecisionReason: "orphan" } },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "allow" } },
  { hookSpecificOutput: { hookEventName: pre, permissionDecision: "allow", additionalContext: "advice" } },
  { reason: "orphan", hookSpecificOutput: { hookEventName: pre, additionalContext: "advice" } },
]) verdict(pre, output, "ERROR");

// A top-level block cannot rescue malformed hook-specific denial metadata.
for (const reason of [undefined, null, "", " \n\t"])
  verdict(pre, { decision: "block", reason: "legacy reason", hookSpecificOutput: {
    hookEventName: pre, permissionDecision: "deny", permissionDecisionReason: reason,
  } }, "ERROR");
for (const tag of [undefined, null, "", " \n\t", post])
  verdict(pre, { decision: "block", reason: "legacy reason", hookSpecificOutput: {
    hookEventName: tag, permissionDecision: "deny", permissionDecisionReason: "hook-specific reason",
  } }, "ERROR");

for (const output of [
  deny, { hookSpecificOutput: { permissionDecision: "deny" } },
  { decision: "block", reason: "blocked", suppressOutput: true },
  { decision: "block", reason: "blocked", updatedMCPToolOutput: "replacement" },
  { hookSpecificOutput: { additionalContext: "advice", updatedMCPToolOutput: "replacement" } },
  { continue: "false" }, { continue: false, stopReason: null },
  { continue: false, decision: "approve" },
  { hookSpecificOutput: { additionalContext: "advice" } },
  { decision: "block", reason: "feedback", hookSpecificOutput: {} },
  { reason: "orphan", hookSpecificOutput: { hookEventName: post, additionalContext: "advice" } },
]) verdict(post, output, "ERROR");

for (const event of [pre, post]) {
  verdict(event, undefined, "ERROR", { error: new Error("spawn failed"), status: null });
  verdict(event, undefined, "ERROR", { signal: "SIGTERM", status: null });
  verdict(event, undefined, "ERROR", { status: 1, stderr: "engine crash" });
  for (const stderr of ["", " \n\t"])
    verdict(event, undefined, "ERROR", { status: 2, stderr });
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

// Fault injection asks whether a broken pack still refuses; ordinary runs keep ERROR.
const failClosed = { status: 0, stderr: "", stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: pre,
  permissionDecision: "deny", permissionDecisionReason: "Blocked because a policy pack this machine is configured to enforce is not running" } }) };
assert.equal(classify(pre, failClosed).verdict, "ERROR");
assert.equal(classify(pre, failClosed, "claude", { failClosed: true }).verdict, "DENY");
assert.equal(classify(pre, { status: 2, stdout: "", stderr: "failproofai could not evaluate this call" }, "claude", { failClosed: true }).verdict, "DENY");
assert.equal(classify(pre, { status: 0, stdout: "", stderr: "failproofaid could not be reached" }, "claude", { failClosed: true }).verdict, "ALLOW");
assert.equal(classify(pre, { status: 1, stdout: "", stderr: "failproofaid could not be reached" }, "claude", { failClosed: true }).verdict, "ERROR");
