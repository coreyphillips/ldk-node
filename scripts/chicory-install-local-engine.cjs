#!/usr/bin/env node
'use strict';

// Install only the exact reviewed local bundles. npm install may replace them;
// rerun this script before rebuilding the isolated iOS compatibility app.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const manifest = require('./chicory-local-engine-manifest.json');

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

function main() {
  const args = process.argv.slice(2);
  const check = args[0] === '--check';
  if (check) args.shift();
  if (args.length !== 2) throw new Error('Usage: chicory-install-local-engine.cjs [--check] /path/to/beignet-portable-engine /path/to/chicory');
  const source = path.resolve(args[0]);
  const project = path.resolve(args[1]);
  const target = path.join(project, 'node_modules/@beignet/portable-engine');
  if (!fs.lstatSync(target).isDirectory()) throw new Error('Installed dependency must be a real directory');
  for (const directory of [source, target]) {
    const pkg = JSON.parse(readRegular(path.join(directory, 'package.json')));
    if (pkg.name !== '@beignet/portable-engine' || pkg.upstreamCommit !== manifest.upstream_beignet_revision) {
      throw new Error('Unsupported portable-engine source revision; refusing to overwrite');
    }
  }
  for (const [file, expected] of Object.entries(manifest.source_files)) {
    if (digest(readRegular(path.join(source, file))) !== expected) throw new Error(`Local source differs from reviewed patch: ${file}`);
  }
  const records = Object.entries(manifest.bundles).map(([file, hashes]) => {
    const bytes = readRegular(path.join(source, file));
    const existing = readRegular(path.join(target, file));
    if (digest(bytes) !== hashes.patched) throw new Error(`Rebuild the reviewed local source before installation: ${file}`);
    const current = digest(existing);
    if (![hashes.original, hashes.patched].includes(current)) throw new Error(`Installed bundle has unrelated changes: ${file}`);
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
