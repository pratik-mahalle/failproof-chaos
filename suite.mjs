// Shared schema-1 validation for the runner and case-drafting CLI.
export function validateCorpus(data) {
  if (!data || typeof data !== "object" || Array.isArray(data))
    throw new Error("Corpus must be an object with schemaVersion 1 and a nonempty cases array");
  if (data.schemaVersion !== 1) throw new Error("Corpus schemaVersion must be 1");
  const plain = (text) => String(text).replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, " ");
  const extra = Object.keys(data).find((key) => !["schemaVersion", "cases"].includes(key));
  if (extra !== undefined) throw new Error(`Corpus field ${plain(extra)} is unsupported`);
  if (!Array.isArray(data.cases) || !data.cases.length)
    throw new Error("Corpus cases must be a nonempty array");
  const fields = ["id", "cat", "target", "tier", "event", "tool_name", "tool_input", "tool_response", "coverage", "note", "expect"];
  const seen = new Set();
  return data.cases.map((c, index) => {
    const fail = (message) => {
      const label = typeof c?.id === "string" ? ` ${JSON.stringify(plain(c.id))}` : "";
      throw new Error(`Corpus case${label} at index ${index}: ${message}`);
    };
    if (!c || typeof c !== "object" || Array.isArray(c)) fail("must be an object");
    const extra = Object.keys(c).find((key) => !fields.includes(key));
    if (extra !== undefined) fail(`field ${plain(extra)} is unsupported`);
    for (const field of ["id", "cat", "target", "tool_name"])
      if (typeof c[field] !== "string" || !c[field].trim()) fail(`${field} must be a nonempty string`);
    if (seen.has(c.id)) fail("id must be unique within the corpus");
    if (!["direct", "evasion", "benign"].includes(c.tier)) fail("tier must be direct, evasion, or benign");
    if (!["PreToolUse", "PostToolUse"].includes(c.event)) fail("event must be PreToolUse or PostToolUse");
    if (!c.tool_input || typeof c.tool_input !== "object" || Array.isArray(c.tool_input)) fail("tool_input must be an object");
    if (!["ALLOW", "DENY", "ASK", "FLAG", "INSTRUCT"].includes(c.expect))
      fail("expect must be ALLOW, DENY, ASK, FLAG, or INSTRUCT");
    const benign = c.tier === "benign";
    if (benign && c.expect !== "ALLOW") fail("expect must be ALLOW for tier benign");
    const coverage = c.coverage === undefined ? (benign ? "benign" : "exploratory") : c.coverage;
    if (!(benign ? coverage === "benign" : ["documented", "exploratory"].includes(coverage)))
      fail(benign ? "coverage must be benign for tier benign" : "coverage must be documented or exploratory for an attack");
    if (c.note !== undefined && typeof c.note !== "string") fail("note must be a string");
    seen.add(c.id);
    return { ...c, coverage, note: c.note ?? "" };
  });
}
