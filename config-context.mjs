// Source identities only: never infer effective parameters or import policy code.
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const code = (error) => /^[A-Z][A-Z0-9_]+$/.test(error?.code) ? error.code : "IO_ERROR";
const idPattern = /^[A-Za-z0-9._-]{1,64}\/[A-Za-z0-9._-]{1,64}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const shaPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{7,40}$/i;
const strings = (value, pattern) => value === undefined ||
  (Array.isArray(value) && value.every((item) => typeof item === "string" && pattern.test(item)));

function readSource(path) {
  const record = { path: resolve(path) };
  try {
    const bytes = readFileSync(record.path);
    record.sha256 = digest(bytes);
    let data;
    try { data = JSON.parse(bytes.toString("utf8")); } catch {
      return { record: { ...record, status: "invalid", code: "INVALID_JSON" } };
    }
    if (!object(data)) return { record: { ...record, status: "invalid", code: "INVALID_OBJECT" } };
    return { record: { ...record, status: "present" }, data };
  } catch (error) {
    return { record: { ...record, status: error.code === "ENOENT" ? "missing" : "error", code: code(error) } };
  }
}

function projectRoot(cwd) {
  let dir = resolve(cwd);
  // Matches the source lookup in pinned engines 1.0.3, 1.0.9 and 1.0.10.
  while (dir !== homedir()) {
    try { if (statSync(join(dir, ".failproofai")).isDirectory()) return dir; } catch {}
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(cwd);
}

function packIdentity(pack, root) {
  if (!object(pack) || typeof pack.id !== "string" || !idPattern.test(pack.id) ||
      typeof pack.version !== "string" || !versionPattern.test(pack.version) ||
      typeof pack.sha256 !== "string" || !shaPattern.test(pack.sha256) ||
      (pack.commit !== undefined && (typeof pack.commit !== "string" || !commitPattern.test(pack.commit.trim()))) ||
      !strings(pack.enabled, /^[A-Za-z0-9._-]{1,128}$/) ||
      !strings(pack.clis, /^[a-z0-9_-]{1,32}$/) ||
      (pack.effect !== undefined && !["enforce", "observe"].includes(pack.effect))) {
    return { status: "invalid", code: "INVALID_PACK_METADATA" };
  }
  const identity = {
    id: pack.id, version: pack.version, sha256: pack.sha256,
    ...(pack.commit === undefined ? {} : { commit: pack.commit.trim().toLowerCase() }),
    enabled: pack.enabled === undefined ? null : [...pack.enabled],
    effect: pack.effect ?? null, clis: pack.clis === undefined ? null : [...pack.clis],
  };
  if (typeof pack.entry !== "string" || !pack.entry) {
    return { ...identity, artifact: { status: "unavailable", code: "NO_ARTIFACT_ENTRY" } };
  }
  try {
    const directory = realpathSync(root);
    const path = realpathSync(resolve(root, pack.entry));
    if (!path.startsWith(directory + sep)) {
      return { ...identity, artifact: { status: "invalid", code: "ARTIFACT_OUTSIDE_PACK_DIR" } };
    }
    const sha256 = digest(readFileSync(path));
    return { ...identity, artifact: { path, sha256, status: sha256 === pack.sha256 ? "verified" : "mismatch" } };
  } catch (error) {
    return { ...identity, artifact: { status: error.code === "ENOENT" ? "missing" : "error", code: code(error) } };
  }
}

export function captureContext({ cwd, adapter, mode, env = process.env, isolationPacks = null }) {
  const testedCwd = resolve(cwd);
  const project = projectRoot(testedCwd);
  const home = resolve(testedCwd, env.FAILPROOFAI_HOME || join(homedir(), ".failproofai"));
  const root = resolve(testedCwd, env.FAILPROOFAI_PACK_DIR || join(home, "policies", "packs"));
  const configFiles = [
    ["project", join(project, ".failproofai", "policies-config.json")],
    ["local", join(project, ".failproofai", "policies-config.local.json")],
    ["user", join(home, "policies-config.json")],
  ].map(([scope, path]) => ({ scope, ...readSource(path).record }));
  let { record: manifest, data } = readSource(join(root, "installed.json"));
  let packs = null;
  if (mode === "isolated") {
    // The runner rewrites this manifest for every case; its last hash is not the run's selection.
    manifest = { path: manifest.path, status: "per-case" };
    packs = Array.isArray(isolationPacks) ? isolationPacks.map((pack) =>
      packIdentity({ ...pack, enabled: undefined, effect: "enforce", clis: [adapter] }, root)) : null;
  } else if (data) {
    if (data.schemaVersion !== 1 || !Array.isArray(data.packs)) {
      manifest = { ...manifest, status: "invalid", code: "UNSUPPORTED_MANIFEST" };
    } else packs = data.packs.map((pack) => packIdentity(pack, root));
  }
  return {
    schemaVersion: 1, adapter, mode, cwd: testedCwd, projectRoot: project,
    evidence: "source-fingerprints-only",
    parameters: mode === "isolated" ? "defaults" : "not-inspected",
    selection: mode === "isolated" ? "each-case-target" : "installed-manifest",
    configFiles, manifest, packs,
  };
}
