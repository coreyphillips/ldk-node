#!/usr/bin/env node
'use strict';

// Install only the exact reviewed local bundles. npm install may replace them;
// rerun this script before rebuilding the isolated iOS compatibility app.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const manifest = require('./chicory-local-engine-updates-manifest.json');

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function readRegular(file) {
  if (!fs.lstatSync(file).isFile()) throw new Error(`Expected a regular file: ${file}`);
  return fs.readFileSync(file);
}
function replace(file, bytes) {
  const pending = `${file}.local-pending`;
  const fd = fs.openSync(pending, 'wx', 0o644);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(pending, file);
  const directory = fs.openSync(path.dirname(file), 'r');
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

function verifySource(source) {
  for (const [file, expected] of Object.entries(manifest.source_files)) {
    if (digest(readRegular(path.join(source, file))) !== expected) throw new Error(`Local source differs from reviewed patches: ${file}`);
  }
}

function reviewedPatches() {
  return manifest.patches.map(record => {
    const file = path.resolve(__dirname, '..', record.file);
    if (digest(readRegular(file)) !== record.sha256) throw new Error(`Reviewed patch differs: ${record.file}`);
    return { ...record, file };
  });
}

function prepareSource(source, check) {
  const patches = reviewedPatches();
  try {
    verifySource(source);
    console.log(JSON.stringify({ checked: true, prepared: true, source_revision: manifest.source_revision }));
    return;
  } catch { /* An original checkout is validated before applying anything. */ }
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).trim();
  const start = head === manifest.source_base_revision ? 0 :
    head === manifest.source_compatibility_revision ? 1 :
      head === manifest.source_trusted_splice_base_revision ? 2 :
        head === manifest.source_invoice_binding_base_revision ? 3 : -1;
  if (start < 0) throw new Error('Source must be a reviewed base, compatibility, receipt or trusted-splice revision');
  if (execFileSync('git', ['status', '--porcelain'], { cwd: source, encoding: 'utf8' }).trim()) {
    throw new Error('Source checkout has local edits; use a clean isolated checkout');
  }
  // Apply all patches to an archive first, then verify every final source hash.
  // A failed later patch therefore cannot leave the caller half-updated.
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'chicory-engine-preflight-'));
  try {
    const archive = execFileSync('git', ['archive', head], { cwd: source, maxBuffer: 64 * 1024 * 1024 });
    execFileSync('tar', ['-x', '-C', stage], { input: archive });
    for (const patch of patches.slice(start)) {
      execFileSync('git', ['apply', '--check', patch.file], { cwd: stage });
      execFileSync('git', ['apply', patch.file], { cwd: stage });
    }
    verifySource(stage);
    if (!check) {
      for (const patch of patches.slice(start)) execFileSync('git', ['apply', patch.file], { cwd: source });
      verifySource(source);
    }
  } finally { fs.rmSync(stage, { recursive: true, force: true }); }
  console.log(JSON.stringify({ checked: true, prepared: !check, source_revision: manifest.source_revision,
    next: 'Run npm run build, then invoke this installer with the Chicory project path.' }));
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const prepare = args.includes('--prepare-source');
  for (const flag of ['--check', '--prepare-source']) {
    const index = args.indexOf(flag);
    if (index >= 0) args.splice(index, 1);
  }
  if (args.length !== (prepare ? 1 : 2)) throw new Error('Usage: chicory-install-local-engine.cjs [--check] /path/to/beignet-portable-engine /path/to/chicory; or --prepare-source [--check] /path/to/clean/source');
  const source = path.resolve(args[0]);
  if (prepare) return prepareSource(source, check);
  reviewedPatches();
  const project = path.resolve(args[1]);
  const target = path.join(project, 'node_modules/@beignet/portable-engine');
  if (!fs.lstatSync(target).isDirectory()) throw new Error('Installed dependency must be a real directory');
  for (const directory of [source, target]) {
    const pkg = JSON.parse(readRegular(path.join(directory, 'package.json')));
    if (pkg.name !== '@beignet/portable-engine' || pkg.upstreamCommit !== manifest.upstream_beignet_revision) {
      throw new Error('Unsupported portable-engine source revision; refusing to overwrite');
    }
  }
  verifySource(source);
  const records = Object.entries(manifest.bundles).map(([file, hashes]) => {
    const bytes = readRegular(path.join(source, file));
    const existing = readRegular(path.join(target, file));
    if (digest(bytes) !== hashes.patched) throw new Error(`Rebuild the reviewed local source before installation: ${file}`);
    const current = digest(existing);
    if (!Object.values(hashes).includes(current)) throw new Error(`Installed bundle has unrelated changes: ${file}`);
    return { file, hashes, bytes, existing, current };
  });
  const backup = path.join(target, '.local-primary-compatibility');
  // Preflight every destination and backup before replacing any installed file.
  for (const record of records) {
    const saved = path.join(backup, path.basename(record.file));
    if (fs.existsSync(saved) && digest(readRegular(saved)) !== record.hashes.original) throw new Error('Existing original backup differs; refusing to overwrite');
    if (fs.existsSync(path.join(target, `${record.file}.local-pending`))) throw new Error('An interrupted install has a pending file; inspect it before retrying');
  }
  if (!check) {
    fs.mkdirSync(backup, { recursive: true, mode: 0o700 });
    for (const record of records) {
      const saved = path.join(backup, path.basename(record.file));
      if (record.current === record.hashes.original && !fs.existsSync(saved)) {
        const fd = fs.openSync(saved, 'wx', 0o600);
        try { fs.writeFileSync(fd, record.existing); fs.fsyncSync(fd); }
        finally { fs.closeSync(fd); }
      }
      if (record.current !== record.hashes.patched) replace(path.join(target, record.file), record.bytes);
    }
    replace(path.join(backup, 'manifest.json'), Buffer.from(JSON.stringify(manifest, null, 2) + '\n'));
  }
  console.log(JSON.stringify({ checked: true, installed: !check, source_revision: manifest.source_revision,
    bundles: Object.fromEntries(records.map(record => [record.file, record.hashes.patched])) }, null, 2));
}

try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
