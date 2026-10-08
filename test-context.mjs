import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureContext } from "./config-context.mjs";

const work = realpathSync(mkdtempSync(join(tmpdir(), "failproof-context-check-")));
const project = join(work, "project");
const cwd = join(project, "nested");
const home = join(work, "home");
const root = join(work, "separate-packs");
const projectFile = join(project, ".failproofai", "policies-config.json");
const localFile = join(project, ".failproofai", "policies-config.local.json");
const userFile = join(home, "policies-config.json");
const manifestFile = join(root, "installed.json");
const artifact = join(root, "guard.mjs");
const env = { FAILPROOFAI_HOME: home, FAILPROOFAI_PACK_DIR: root, SECRET_TOKEN: "environment-secret" };
const capture = (overrides = {}) => captureContext({ cwd, adapter: "claude", mode: "combined", env, ...overrides });
const writeJSON = (path, value) => writeFileSync(path, JSON.stringify(value));
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

try {
  for (const path of [cwd, join(project, ".failproofai"), home, root]) mkdirSync(path, { recursive: true });
  const empty = capture();
  assert.equal(empty.cwd, cwd);
  assert.equal(empty.projectRoot, project);
  assert.deepEqual(empty.configFiles.map((file) => file.status), ["missing", "missing", "missing"]);
  assert.equal(empty.manifest.status, "missing");
  assert.equal(empty.packs, null);
  assert.equal(empty.configFiles[2].path, userFile);
  assert.equal(empty.manifest.path, manifestFile);
  assert.deepEqual(empty, capture());
  const relative = capture({ env: { FAILPROOFAI_HOME: "local-home", FAILPROOFAI_PACK_DIR: "local-packs" } });
  assert.equal(relative.configFiles[2].path, join(cwd, "local-home", "policies-config.json"));
  assert.equal(relative.manifest.path, join(cwd, "local-packs", "installed.json"));

  writeJSON(projectFile, { policyParams: { guard: { value: "project-secret" } } });
  writeJSON(localFile, { policyParams: { guard: { value: "local-secret" } } });
  writeJSON(userFile, { policyParams: { guard: { value: "user-secret" } } });
  writeJSON(join(home, "credentials.json"), { token: "credential-secret" });
  writeFileSync(artifact, "throw new Error('Must never import this artifact');\n");
  const pack = { id: "example/guards", version: "1.0.0", entry: "guard.mjs", sha256: hash(artifact),
    commit: "a".repeat(40), source: "https://example.test/?fixture=source-secret", extra: { secret: "manifest-secret" } };
  const writeManifest = (entry = pack) => writeJSON(manifestFile, { schemaVersion: 1, packs: [entry] });
  writeManifest();
  const before = [projectFile, localFile, userFile, manifestFile, artifact].map(hash);
  const context = capture();
  assert.deepEqual(context.configFiles.map((file) => file.scope), ["project", "local", "user"]);
  assert.deepEqual(context.configFiles.map((file) => file.sha256), before.slice(0, 3));
  assert.equal(context.evidence, "source-fingerprints-only");
  assert.equal(context.parameters, "not-inspected");
  assert.equal(context.packs[0].enabled, null);
  assert.equal(context.packs[0].effect, null);
  assert.equal(context.packs[0].clis, null);
  assert.equal(context.packs[0].artifact.status, "verified");
  assert.equal(context.packs[0].artifact.sha256, pack.sha256);
  assert.doesNotMatch(JSON.stringify(context), /(?:project|local|user|credential|environment|source|manifest)-secret/);
  assert.deepEqual(before, [projectFile, localFile, userFile, manifestFile, artifact].map(hash));
  writeJSON(localFile, { policyParams: { guard: { value: "changed-secret" } } });
  const changed = capture();
  assert.equal(changed.configFiles[0].sha256, context.configFiles[0].sha256);
  assert.notEqual(changed.configFiles[1].sha256, context.configFiles[1].sha256);
  assert.equal(changed.configFiles[2].sha256, context.configFiles[2].sha256);
  assert.equal(changed.projectRoot, project); // Identify all sources; do not merge their parameters.

  writeManifest({ ...pack, enabled: [], clis: [], effect: "observe" });
  assert.deepEqual(capture().packs[0].enabled, []);
  assert.deepEqual(capture().packs[0].clis, []);
  assert.equal(capture().packs[0].effect, "observe");
  writeManifest({ ...pack, commit: ` ${"A".repeat(40)} ` });
  assert.equal(capture().packs[0].commit, "a".repeat(40));
  writeFileSync(artifact, "changed artifact\n");
  assert.equal(capture().packs[0].artifact.status, "mismatch");
  writeManifest({ ...pack, entry: "missing.mjs" });
  assert.equal(capture().packs[0].artifact.status, "missing");
  const outside = join(work, "outside.mjs");
  writeFileSync(outside, "outside-secret");
  symlinkSync(outside, join(root, "escape.mjs"));
  writeManifest({ ...pack, entry: "escape.mjs" });
  assert.equal(capture().packs[0].artifact.code, "ARTIFACT_OUTSIDE_PACK_DIR");
  writeManifest({ ...pack, enabled: [{ secret: "nested-secret" }] });
  assert.deepEqual(capture().packs, [{ status: "invalid", code: "INVALID_PACK_METADATA" }]);
  writeJSON(manifestFile, { schemaVersion: 2, packs: [] });
  assert.equal(capture().manifest.code, "UNSUPPORTED_MANIFEST");
  assert.equal(capture().packs, null);
  writeFileSync(manifestFile, "{bad secret JSON");
  assert.equal(capture().manifest.code, "INVALID_JSON");
  assert.equal(capture().packs, null);
  writeJSON(manifestFile, []);
  assert.equal(capture().manifest.code, "INVALID_OBJECT");
  rmSync(manifestFile);
  mkdirSync(manifestFile);
  assert.equal(capture().manifest.status, "error");
  assert.equal(capture().packs, null);
  rmSync(manifestFile, { recursive: true });
  writeFileSync(userFile, "{malformed");
  assert.equal(capture().configFiles[2].code, "INVALID_JSON");
  rmSync(userFile);
  mkdirSync(userFile);
  assert.equal(capture().configFiles[2].status, "error");
  rmSync(userFile, { recursive: true });
  writeJSON(userFile, {});
  if (process.getuid?.() !== 0) {
    chmodSync(userFile, 0);
    try { assert.equal(capture().configFiles[2].code, "EACCES"); } finally { chmodSync(userFile, 0o600); }
  }

  const isolated = join(work, "isolated");
  const isolatedHome = join(isolated, ".failproofai");
  const isolatedRoot = join(isolatedHome, "policies", "packs");
  mkdirSync(isolatedRoot, { recursive: true });
  writeFileSync(join(isolatedRoot, "guard.mjs"), readFileSync(artifact));
  const isolatedPack = { ...pack, sha256: hash(artifact) };
  writeJSON(join(isolatedRoot, "installed.json"), { schemaVersion: 1, packs: [{ ...isolatedPack, enabled: ["last-case-only"] }] });
  const result = capture({ cwd: isolated, adapter: "codex", mode: "isolated", isolationPacks: [isolatedPack],
    env: { FAILPROOFAI_HOME: isolatedHome } });
  assert.equal(result.projectRoot, isolated);
  assert.equal(result.parameters, "defaults");
  assert.equal(result.selection, "each-case-target");
  assert.equal(result.manifest.status, "per-case");
  assert.equal(result.manifest.sha256, undefined);
  assert.deepEqual(result.configFiles.map((file) => file.status), ["missing", "missing", "missing"]);
  assert.equal(result.packs[0].enabled, null);
  assert.equal(result.packs[0].effect, "enforce");
  assert.deepEqual(result.packs[0].clis, ["codex"]);
  assert.equal(result.packs[0].artifact.status, "verified");
  assert.doesNotMatch(JSON.stringify(result), /last-case-only|secret/);
  assert.equal(capture({ cwd: join(work, "no-marker") }).projectRoot, join(work, "no-marker"));
  mkdirSync(join(cwd, ".failproofai"));
  assert.equal(capture().projectRoot, cwd);
  console.log("configuration context checks passed");
} finally {
  rmSync(work, { recursive: true, force: true });
}
