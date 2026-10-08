// Decode emitted hook decisions; this does not run or verify a live agent.
export function classify(event, p, adapter = "claude") {
  if (adapter === "codex") return classifyCodex(event, p);
  if (adapter !== "claude") return { verdict: "ERROR", reason: `unsupported adapter: ${adapter}` };
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

// Bounded contract: https://learn.chatgpt.com/docs/hooks (2026-10-08).
// Reject unsupported output so an inert response cannot count as protection.
// Parser details: openai/codex@e974aad3b1a8f144273e882c614aefe69eaef615,
// codex-rs/hooks/src/{schema.rs,engine/output_parser.rs,events/pre_tool_use.rs,events/post_tool_use.rs}.
function classifyCodex(event, p) {
  const error = (reason) => ({ verdict: "ERROR", reason });
  const post = event === "PostToolUse";
  const feedback = (reason) => ({ verdict: "FLAG", reason: `Post-tool feedback (tool already ran): ${reason}` });
  if (!["PreToolUse", "PostToolUse"].includes(event)) return error(`unsupported Codex event: ${event}`);
  if (!p.error && !p.signal && p.status === 2 && !p.stderr?.trim())
    return error("Codex hook exited 2 without a nonempty reason on stderr");
  if (p.error || p.signal || p.status !== 0 ||
      /could not evaluate this call|failproofaid could not be reached|different protocol version|policy pack this machine is configured to enforce is not running/.test(`${p.stdout}\n${p.stderr}`)) {
    const result = classify(event, p);
    return post && result.verdict === "DENY" ? feedback(result.reason) : result;
  }
  const text = p.stdout?.trim();
  if (!text) return { verdict: "ALLOW", reason: "no decision emitted" };
  let out;
  try { out = JSON.parse(text); } catch { return error("invalid JSON from engine"); }
  const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  if (!object(out)) return error("invalid hook response");
  const keys = ["hookSpecificOutput", "decision", "reason", "systemMessage", ...(post ? ["continue", "stopReason"] : [])];
  const extra = Object.keys(out).find((key) => !keys.includes(key));
  if (extra !== undefined) return error(`unsupported Codex response field: ${extra}`);
  const hso = out.hookSpecificOutput === undefined ? {} : out.hookSpecificOutput;
  if (!object(hso)) return error("invalid hookSpecificOutput");
  const hookKeys = ["hookEventName", "additionalContext", ...(!post ? ["permissionDecision", "permissionDecisionReason"] : [])];
  const extraHook = Object.keys(hso).find((key) => !hookKeys.includes(key));
  if (extraHook !== undefined) return error(`unsupported Codex hookSpecificOutput field: ${extraHook}`);
  if (out.hookSpecificOutput !== undefined && hso.hookEventName !== event)
    return error("Codex hookSpecificOutput requires hookEventName matching the case event");
  for (const [key, value] of Object.entries({ reason: out.reason, systemMessage: out.systemMessage,
    stopReason: out.stopReason, additionalContext: hso.additionalContext, permissionDecisionReason: hso.permissionDecisionReason }))
    if (value !== undefined && typeof value !== "string") return error(`invalid Codex ${key}`);
  if (out.continue !== undefined && typeof out.continue !== "boolean") return error("invalid Codex continue");
  if (out.decision !== undefined && out.decision !== "block") return error(`unsupported Codex decision: ${String(out.decision)}`);
  // Codex accepts permissionDecision:allow only with updatedInput, which this
  // decision-only runner does not measure and rejects above.
  if (hso.permissionDecision !== undefined && hso.permissionDecision !== "deny")
    return error(`unsupported Codex permissionDecision: ${String(hso.permissionDecision)}`);
  if (hso.permissionDecision === "deny" && !hso.permissionDecisionReason?.trim())
    return error("Codex deny requires a nonempty permissionDecisionReason");
  if (hso.permissionDecisionReason !== undefined && hso.permissionDecision === undefined)
    return error("Codex permissionDecisionReason requires permissionDecision");
  if (out.reason !== undefined && out.decision === undefined &&
      (post ? out.continue !== false : hso.permissionDecision === undefined))
    return error("Codex reason requires a decision");
  if (out.decision === "block" && !out.reason?.trim()) return error("Codex block requires a nonempty reason");
  const context = hso.additionalContext?.trim();
  if (post && (out.decision === "block" || out.continue === false))
    return feedback(out.reason || out.stopReason || context || "hook stopped normal tool-result processing");
  if (hso.permissionDecision === "deny" || out.decision === "block")
    return { verdict: "DENY", reason: hso.permissionDecisionReason ?? out.reason };
  if (context) return { verdict: post ? "FLAG" : "INSTRUCT", reason: context };
  if (out.continue === true) return { verdict: "ALLOW", reason: "permissive decision" };
  return error("response contains no recognized Codex decision or context");
}
