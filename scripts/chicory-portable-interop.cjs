#!/usr/bin/env node
'use strict';

// Funded regtest against the exact portable engine and wallet-core installed in
// Chicory. Native iOS and direct Iroh need their explicit test flags. Optional
// offline and direct-funding assertions also require CHICORY_TEST_* flags.
// Build first: cargo build --features chicory --example chicory-primary
// Run: node scripts/chicory-portable-interop.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const readline = require('node:readline');
const { randomBytes } = require('node:crypto');
const { execFileSync, spawn } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const source = process.env.BEIGNET_SOURCE_DIR || path.resolve(root, '../../testing/beignet');
const binary = process.env.CHICORY_PRIMARY_BIN || path.join(root, 'target/debug/examples/chicory-primary');
const electrum = new URL(process.env.CHICORY_ELECTRUM_URL || 'tcp://127.0.0.1:60001');
const primaryChainSource = process.env.CHICORY_PRIMARY_CHAIN_SOURCE ||
  'rpc://polaruser:polarpass@127.0.0.1:43782';
const container = process.env.BEIGNET_REGTEST_BITCOIN || 'bitcoin';
const timeoutMs = Number(process.env.CHICORY_TEST_TIMEOUT_MS || 180000);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const evidence = { scope: 'installed-chicory-portable', checks: [] };
const chicory = process.env.CHICORY_SOURCE_DIR || path.resolve(root, '../../testing/chicory');
const portable = path.join(chicory, 'node_modules/@beignet/portable-engine');
const walletCore = path.join(chicory, 'node_modules/@beignet/wallet-core');
const { pathToFileURL } = require('node:url');
const { createHash } = require('node:crypto');
const tls = require('node:tls');

function btc(...args) {
  return execFileSync('docker', [
    'exec', container, 'bitcoin-cli', '-rpcport=43782',
    '-rpcuser=polaruser', '-rpcpassword=polarpass', '-rpcwallet=default', ...args,
  ], { encoding: 'utf8', timeout: 30000, maxBuffer: 2 * 1024 * 1024 }).trim();
}

function pass(name, details = {}) {
  evidence.checks.push({ name, ...details });
  console.log('PASS ' + name);
}

async function wait(name, read, limit = timeoutMs) {
  const deadline = Date.now() + limit;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await read();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await delay(500);
  }
  throw new Error(name + ' timed out' + (lastError ? ': ' + lastError.message : ''));
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function startPrimary(dataDir, port) {
  const child = spawn(binary, [dataDir, String(port), primaryChainSource], {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe'],
  });
  const pending = new Map();
  let serial = 0;
  let stderr = '';
  let readyResolve;
  let readyReject;
  const readyPromise = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const readyTimer = setTimeout(() => readyReject(new Error('Primary startup timed out')), timeoutMs);
  child.stderr.on('data', bytes => {
    stderr = (stderr + bytes.toString()).slice(-8000);
  });
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', line => {
    let message;
    try { message = JSON.parse(line); }
    catch { return; }
    if (message.ready === true) {
      clearTimeout(readyTimer);
      readyResolve(message);
      return;
    }
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) request.reject(new Error(message.error));
    else request.resolve(message.result);
  });
  const failed = error => {
    clearTimeout(readyTimer);
    readyReject(error);
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    pending.clear();
  };
  child.on('error', failed);
  const exited = new Promise(resolve => {
    child.once('close', (code, signal) => {
      failed(new Error(`Primary exited (${code ?? signal}): ${stderr}`));
      lines.close();
      resolve({ code, signal });
    });
  });
  const request = (method, fields = {}) => new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      reject(new Error('Primary is stopped'));
      return;
    }
    const id = ++serial;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Primary ${method} timed out`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(JSON.stringify({ id, method, ...fields }) + '\n', error => {
      if (!error) return;
      pending.delete(id);
      clearTimeout(timer);
      reject(error);
    });
  });
  try {
    const ready = await readyPromise;
    assert.match(ready.nodeId, /^0[23][0-9a-f]{64}$/);
    assert.match(ready.address, /^bcrt1/);
    return {
      ready, request, child,
      async stop() {
        if (child.exitCode === null && child.signalCode === null) {
          try { await request('stop'); }
          catch { child.kill('SIGTERM'); }
          child.stdin.end();
          const kill = setTimeout(() => child.kill('SIGKILL'), 15000);
          await exited;
          clearTimeout(kill);
        }
      },
    };
  } catch (error) {
    child.kill('SIGKILL');
    await exited;
    throw error;
  }
}

function makeVolume(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = name => path.join(directory, 'device-' + Buffer.from(name).toString('hex'));
  return {
    read: name => fs.existsSync(file(name)) ? fs.readFileSync(file(name)) : null,
    write(name, bytes) {
      const destination = file(name);
      const descriptor = fs.openSync(destination + '.tmp', 'w', 0o600);
      try {
        fs.writeFileSync(descriptor, bytes);
        fs.fsyncSync(descriptor);
      } finally { fs.closeSync(descriptor); }
      fs.renameSync(destination + '.tmp', destination);
      const parent = fs.openSync(directory, 'r');
      try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    },
    remove: name => fs.rmSync(file(name), { force: true }),
    rename: (from, to) => fs.renameSync(file(from), file(to)),
    list: prefix => fs.readdirSync(directory).filter(name => name.startsWith('device-'))
      .map(name => Buffer.from(name.slice(7), 'hex').toString())
      .filter(name => !prefix || name.startsWith(prefix)),
  };
}

function fingerprint(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// A second installed phone needs its own process because the portable engine
// owns process globals. Only public proofs cross this child boundary. Seeds,
// receipt preimages, witnesses and serialized wallet records stay on disk.
async function directFundingPayer() {
  assert.equal(JSON.parse(btc('getblockchaininfo')).chain, 'regtest');
  const primaryUri = process.env.CHICORY_DF_PRIMARY_URI;
  const target = /^([0-9a-f]{66})@127\.0\.0\.1:(\d+)$/.exec(primaryUri || '');
  assert.ok(target, 'Direct-funding child requires the local primary URI');
  const port = Number(target[2]);
  const amountSats = Number(process.env.CHICORY_DF_AMOUNT_SATS);
  assert.ok(Number.isSafeInteger(amountSats) && amountSats > 0 && amountSats <= 15000);
  const request = process.env.CHICORY_DF_REQUEST_URI;
  const encoded = new URL(request).searchParams.get('bgnq');
  assert.ok(encoded, 'The installed receiver must create a direct-funding envelope');
  const { decodeAndVerifyRequestEnvelope } = require(path.join(source, 'dist/lightning/direct-funding/envelope.js'));
  const envelope = decodeAndVerifyRequestEnvelope(encoded, {
    expectedChainHash: Buffer.from('06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f', 'hex'),
  });
  assert.equal(Number(envelope.amountSat), amountSats);
  const { createFundingScript } = require(path.join(source, 'dist/lightning/script/funding.js'));
  const { createPortableRuntime } = require(path.join(portable, 'dist/portable.cjs'));
  const { createSqlJsDatabaseFactory } = require(path.join(portable, 'dist/sqljs.cjs'));
  const { EmbeddedWalletClient } = await import(pathToFileURL(path.join(walletCore, 'src/index.js')).href);
  const volume = makeVolume(process.env.CHICORY_DF_CHILD_DIR);
  const databaseFactory = await createSqlJsDatabaseFactory({
    load: volume.read, save: volume.write,
    wasmBinary: fs.readFileSync(require.resolve('sql.js/dist/sql-wasm.wasm', { paths: [portable] })),
  });
  const endpoint = { host: electrum.hostname, port: Number(electrum.port), tls: electrum.protocol === 'ssl:' };
  const sockets = new Set();
  const runtime = await createPortableRuntime({
    volume, databaseFactory, electrum: endpoint,
    socketFactory(destination) {
      assert.ok((destination.host === endpoint.host && destination.port === endpoint.port && destination.tls === endpoint.tls) ||
        (destination.host === '127.0.0.1' && destination.port === port && !destination.tls),
      'Direct-funding child refused an unexpected transport destination');
      const socket = destination.tls ? tls.connect({ host: destination.host, port: destination.port }) :
        net.connect({ host: destination.host, port: destination.port });
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
      return socket;
    },
    nodeOptions: { logger: { debug() {}, info() {}, warn() {}, error() {} } },
  });
  const client = new EmbeddedWalletClient({ runtime });
  const say = (step, value) => console.log('DF_CHILD ' + step + ' ' + JSON.stringify(value));
  try {
    const created = await client.createWallet({
      name: 'Installed direct-funding payer', network: 'regtest', primaryUri, electrum: endpoint,
    });
    const rpc = (route, method = 'GET', body) => runtime.request({
      method, path: `/wallets/${created.id}/api${route}`, body,
    });
    await wait('direct-funding payer paired', async () => {
      const snapshot = await client.snapshot();
      return snapshot.primary.connected && snapshot.primary.setup === 'ready';
    });
    assert.equal((await rpc('/channels')).length, 0);
    const address = (await rpc('/address/new', 'POST', {})).address;
    assert.match(address, /^bcrt1/);
    const depositTxid = btc('sendtoaddress', address, '0.00020000');
    btc('-generate', '1');
    const coin = await wait('payer has one confirmed coin below channelization floor', async () => {
      await client.refreshWallet();
      const coins = await rpc('/utxos');
      return coins.length === 1 && coins[0].valueSats === 20000 && coins[0].height > 0 && coins[0];
    });
    assert.equal((await rpc('/channels')).length, 0, 'The payer must retain its on-chain coin');
    say('coin', { depositTxid, valueSats: coin.valueSats, height: coin.height });
    let conflictTransaction;
    if (process.env.CHICORY_DF_CONFLICT_TEST === '1') {
      // This disposable payer deliberately spends its contributed input twice.
      // Derive only this newly created regtest wallet in memory, and verify the
      // script before signing. Never export its mnemonic or private key.
      const bitcoin = require(require.resolve('bitcoinjs-lib', { paths: [source] }));
      const bip39 = require(require.resolve('bip39', { paths: [source] }));
      const { bip32 } = require(path.join(source, 'dist/utils/ecc-apis.js'));
      const master = bip32.fromSeed(bip39.mnemonicToSeedSync(await client.getRecoveryPhrase()), bitcoin.networks.regtest);
      let signingKey;
      let script;
      for (let branch = 0; branch < 2; branch++) {
        for (let index = 0; index < 20; index++) {
          const key = master.derivePath(`m/84'/1'/0'/${branch}/${index}`);
          const payment = bitcoin.payments.p2wpkh({ pubkey: key.publicKey, network: bitcoin.networks.regtest });
          if (payment.address === coin.address) { signingKey = key; script = payment.output; }
        }
      }
      assert.ok(signingKey && script, 'Conflict fixture must identify its own disposable input');
      const transaction = JSON.parse(btc('getrawtransaction', coin.txid, 'true'));
      assert.equal(transaction.vout[coin.vout].scriptPubKey.hex, script.toString('hex'));
      const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
      psbt.addInput({ hash: coin.txid, index: coin.vout, sequence: 0xfffffffd,
        witnessUtxo: { script, value: coin.valueSats } });
      psbt.addOutput({ address: btc('getnewaddress', 'chicory-conflict', 'bech32'), value: 10000 });
      psbt.signInput(0, signingKey);
      psbt.finalizeAllInputs();
      conflictTransaction = psbt.extractTransaction().toHex();
    }
    const review = await client.prepareSend({ request });
    assert.equal(review.route, 'bitcoin');
    assert.equal(review.method, 'direct-funding', 'The wallet must not fall back to an address or Lightning');
    assert.equal(review.amountSats, amountSats);
    assert.equal(review.feeSats, 1000);
    say('review', { route: review.route, method: review.method, amountSats, feeSats: review.feeSats });
    const sent = await client.send(review);
    assert.ok(['pending', 'completed'].includes(sent.status), sent.message || 'Direct funding was refused');
    assert.match(sent.txid || '', /^[0-9a-f]{64}$/);
    say('sent', { status: sent.status, txid: sent.txid });
    if (conflictTransaction) {
      const candidate = JSON.parse(btc('getrawtransaction', sent.txid, 'true'));
      const inputIndex = candidate.vin.findIndex(input => input.txid === coin.txid && input.vout === coin.vout);
      assert.ok(inputIndex >= 0);
      assert.equal(candidate.confirmations || 0, 0);
      say('conflict', { candidateTxid: sent.txid, spentTxid: coin.txid, spentVout: coin.vout,
        inputIndex, transaction: conflictTransaction });
      return;
    }
    const row = await wait('direct-funding payer Activity confirmed', async () => {
      await client.refreshWallet();
      return (await client.snapshot()).activity.find(item =>
        item.id === `submission:${review.id}` && item.status === 'completed');
    });
    assert.equal(row.txid, sent.txid);
    assert.equal(row.amountSats, amountSats);
    const record = await wait('direct-funding receipt persisted', async () =>
      (await rpc('/direct-funding/payments')).find(item =>
        item.requestId === envelope.requestId.toString('hex') && item.receiptPreimage));
    assert.equal(record.receiptHash, envelope.receiptHash.toString('hex'));
    assert.equal(record.receiverNodeId, envelope.receiverNodeId.toString('hex'));
    assert.equal(Number(record.amountSat), amountSats);
    assert.equal(record.fundingTxid, sent.txid);
    assert.equal(record.spentTxid, depositTxid);
    assert.match(record.receiptPreimage, /^[0-9a-f]{64}$/);
    assert.equal(createHash('sha256').update(Buffer.from(record.receiptPreimage, 'hex')).digest('hex'), record.receiptHash);
    assert.ok(record.attestation, 'The durable payment must retain the receiver attestation');
    const fundingScript = createFundingScript(Buffer.from(record.attestation.localFundingPubkey, 'hex'),
      Buffer.from(record.attestation.remoteFundingPubkey, 'hex')).p2wshOutput.toString('hex');
    const transaction = JSON.parse(btc('getrawtransaction', sent.txid, 'true'));
    assert.ok(transaction.confirmations >= 1);
    assert.ok(transaction.vin.some(input => input.txid === depositTxid && input.vout === record.spentVout));
    assert.equal(transaction.vout[record.attestation.fundingOutputIndex]?.scriptPubKey.hex, fundingScript);
    assert.ok(!(await rpc('/utxos')).some(item => item.txid === depositTxid));
    say('proof', { requestId: record.requestId, receiverNodeId: record.receiverNodeId,
      receiptHash: record.receiptHash, receiptVerified: true, fundingTxid: record.fundingTxid,
      fundingOutputIndex: record.attestation.fundingOutputIndex, fundingScript,
      spentTxid: record.spentTxid, spentVout: record.spentVout,
      amountSats, activityStatus: row.status, activityAmountSats: row.amountSats });
  } finally {
    await runtime.close().catch(() => {});
    for (const socket of sockets) socket.destroy();
  }
}

function startDirectFundingPayer(directory, primaryUri, requestUri, amountSats, conflict = false) {
  const child = spawn(process.execPath, [__filename, '--direct-funding-payer'], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env,
      CHICORY_DF_CHILD_DIR: directory, CHICORY_DF_PRIMARY_URI: primaryUri,
      CHICORY_DF_REQUEST_URI: requestUri, CHICORY_DF_AMOUNT_SATS: String(amountSats),
      CHICORY_DF_CONFLICT_TEST: conflict ? '1' : '0',
    },
  });
  const state = { steps: {}, exited: false, error: null };
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', line => {
    const match = /^DF_CHILD ([a-z]+) (.+)$/.exec(line);
    if (!match) return;
    try { state.steps[match[1]] = JSON.parse(match[2]); }
    catch { state.error = new Error('Malformed direct-funding child evidence'); }
  });
  let stderr = '';
  child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-2000); });
  child.on('error', error => { state.error = error; });
  const closed = new Promise(resolve => child.once('close', code => {
    state.exited = true;
    if (code !== 0) state.error = new Error('Direct-funding payer failed: ' + stderr);
    lines.close();
    resolve();
  }));
  return { state, async stop() {
    if (!state.exited) child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
    await closed;
    clearTimeout(timer);
  } };
}

async function main() {
  assert.ok(['tcp:', 'ssl:'].includes(electrum.protocol));
  const relayIroh = process.env.CHICORY_TEST_IROH_RELAY === '1';
  const discoveryIroh = process.env.CHICORY_TEST_IROH_DISCOVERY === '1';
  const fallbackIroh = process.env.CHICORY_TEST_IROH_FALLBACK === '1';
  const providerRelayIroh = process.env.CHICORY_TEST_IROH_PROVIDER_RELAY === '1';
  if (providerRelayIroh) {
    assert.equal(process.env.CHICORY_TEST_IROH, '1', 'Provider relay qualification requires Iroh');
    assert.equal(process.env.CHICORY_TEST_IOS, '1', 'Provider isolation currently qualifies native iOS');
    assert(!relayIroh && !discoveryIroh && !fallbackIroh, 'Run provider relay isolation separately');
  }
  if (fallbackIroh) {
    assert.equal(process.env.CHICORY_TEST_IROH, '1', 'Fallback qualification requires Iroh');
    assert(!relayIroh && !discoveryIroh, 'Run same-key fallback separately');
  }
  if (relayIroh || discoveryIroh) assert.equal(process.env.CHICORY_TEST_IROH, '1', 'Relay qualification requires Iroh');
  if (discoveryIroh) assert.ok(relayIroh, 'Discovery qualification requires public relays');
  if (relayIroh) assert.notEqual(process.env.CHICORY_TEST_IOS, '1', 'Container relay isolation applies to the Node endpoint only');
  const autoExpireOffline = process.env.CHICORY_TEST_OFFLINE_AUTO_EXPIRE === '1';
  const unpaidOffline = process.env.CHICORY_TEST_OFFLINE_UNPAID === '1' || autoExpireOffline;
  if (unpaidOffline) {
    assert.equal(process.env.CHICORY_TEST_OFFLINE, '1', 'Unpaid reservation qualification requires the offline fixture');
    for (const flag of ['IOS', 'IROH', 'OFFLINE_CONCURRENT', 'RECOVERY', 'RECOVERY_SWEEP',
      'INITIAL_DEPOSIT', 'JIT_SPLICE', 'SPLICES', 'DIRECT_FUNDING', 'CONFLICT', 'SEND_MAX', 'DRAIN']) {
      assert.ok(!process.env['CHICORY_TEST_' + flag], 'Run unpaid reservation retirement as a separate portable fixture');
    }
  }
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 30000 && timeoutMs <= 600000);
  assert.ok(fs.existsSync(binary), 'Build the chicory-primary Rust example first');
  evidence.primaryBinarySha256 = fingerprint(binary);
  const engineFile = path.join(portable, 'dist/portable.cjs');
  const coreFile = path.join(walletCore, 'src/index.js');
  let { createPortableRuntime } = require(engineFile);
  const { createSqlJsDatabaseFactory } = require(path.join(portable, 'dist/sqljs.cjs'));
  let { EmbeddedWalletClient } = await import(pathToFileURL(coreFile).href);
  const { BeignetNode } = require(path.join(source, 'dist/cli/beignet-node.js'));
  const wasmFile = require.resolve('sql.js/dist/sql-wasm.wasm', { paths: [portable] });
  evidence.packages = {
    chicoryVersion: require(path.join(chicory, 'package.json')).version,
    engineUpstreamVersion: require(path.join(portable, 'package.json')).upstreamVersion,
    engineSha256: fingerprint(engineFile), walletCoreSha256: fingerprint(coreFile),
    payerVersion: require(path.join(source, 'package.json')).version,
  };
  const chain = JSON.parse(btc('getblockchaininfo'));
  assert.equal(chain.chain, 'regtest', 'Refusing to fund any network except regtest');
  evidence.chain = chain.chain;
  evidence.startedAt = new Date().toISOString();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ldk-chicory-portable-'));
  const port = await freePort();
  const sockets = new Set();
  const diagnostics = [];
  let primary;
  let payer;
  let runtime;
  let client;
  let rpc;
  let succeeded = false;
  let iosHarness;
  let irohBridge;
  let fallbackTor;
  const fallbackEndpoints = [];
  try {
    if (process.env.CHICORY_TEST_IOS === '1') {
      for (const flag of ['INITIAL_DEPOSIT', 'RECOVERY', 'RECOVERY_SWEEP', 'JIT_SPLICE',
        'SPLICES', 'CONFLICT', 'SEND_MAX', 'DRAIN']) {
        assert.ok(!process.env['CHICORY_TEST_' + flag], 'Native simulator fixture supports baseline, direct funding and offline cases only');
      }
      iosHarness = await require('./chicory-ios-harness.cjs').createIosHarness();
      ({ createPortableRuntime, EmbeddedWalletClient } = iosHarness);
      evidence.scope = 'ios-native-chicory';
    }
    primary = await startPrimary(path.join(temp, 'primary'), port);
    const providerKey = primary.ready.nodeId;
    let walletPrimaryUri = primary.ready.uri;
    let walletPrimaryFallbackUri;
    let iroh;
    if (process.env.CHICORY_TEST_IROH === '1') {
      for (const flag of ['INITIAL_DEPOSIT', 'RECOVERY', 'RECOVERY_SWEEP', 'JIT_SPLICE',
        'SPLICES', 'DIRECT_FUNDING', 'CONFLICT', 'SEND_MAX', 'DRAIN']) {
        assert.ok(!process.env['CHICORY_TEST_' + flag], 'Iroh fixture supports baseline and offline cases only');
      }
      if (process.env.CHICORY_TEST_IOS === '1' && !fallbackIroh) {
        if (providerRelayIroh) {
          const setup = await require('../tools/chicory-iroh/isolated-provider-fixture.cjs')
            .createIsolatedProviderFixture({ directory: temp, port, providerKey, source, evidence });
          irohBridge = setup.bridge; walletPrimaryUri = setup.uri;
        } else {
          const { startBridge } = require('../tools/chicory-iroh/bridge.cjs');
          irohBridge = await startBridge({ identityPath: path.join(temp, 'iroh.key'), port,
            discovery: true, defaultRelays: true });
          const address = irohBridge.address();
          assert(address.relayUrl, 'Native Iroh pairing requires a reachable relay address');
          walletPrimaryUri = providerKey + '@iroh:' + address.endpointId + '?relay=' + encodeURIComponent(address.relayUrl);
          evidence.scope = 'ios-native-chicory-iroh';
          evidence.irohEndpointId = address.endpointId;
          evidence.irohRelayUrl = address.relayUrl;
        }
        // openDeviceWallet selects the actual native Iroh factory from this URI.
      } else if (fallbackIroh) {
        const { startBridge } = require('../tools/chicory-iroh/bridge.cjs');
        irohBridge = await startBridge({ identityPath: path.join(temp, 'iroh.key'), port,
          discovery: false, defaultRelays: true });
        const address = irohBridge.address();
        walletPrimaryUri = providerKey + '@iroh:' + address.endpointId + '?relay=' + encodeURIComponent(address.relayUrl);
        await irohBridge.close();
        evidence.irohFallback = { primaryEndpointStopped: true };
        fallbackTor = await require('../tools/chicory-iroh/tor-fixture.cjs').startTor({ port, evidence: evidence.irohFallback });
        walletPrimaryFallbackUri = providerKey + '@' + fallbackTor.host + ':' + fallbackTor.port;
        if (iosHarness) {
          iosHarness.authorizePrimaryFallback(walletPrimaryUri, walletPrimaryFallbackUri);
          evidence.scope = 'ios-native-chicory-same-key-onion-fallback';
          evidence.irohFallback.nativeTor = true;
          evidence.irohFallback.nativeDialCountersInstrumented = false;
        } else {
          const { createNodeIrohEndpoint } = require(path.join(source, 'dist/lightning/transport/iroh-node.js'));
          evidence.scope = 'installed-chicory-portable-same-key-onion-fallback';
          evidence.irohFallback.attempts = 0;
          evidence.irohFallback.unexpectedIrohConnections = 0;
          iroh = { discovery: false, factory: async options => {
            const endpoint = await createNodeIrohEndpoint({ ...options, discovery: false });
            fallbackEndpoints.push(endpoint);
            const connect = endpoint.connect.bind(endpoint);
            endpoint.connect = async (target, timeout) => {
              evidence.irohFallback.attempts++;
              const socket = await connect(target, timeout);
              evidence.irohFallback.unexpectedIrohConnections++;
              return socket;
            };
            return endpoint;
          } };
        }
      } else if (relayIroh) {
        const setup = await require('../tools/chicory-iroh/relay-fixture.cjs').createRelayFixture({
          directory: temp, port, providerKey, discovery: discoveryIroh, source, evidence,
        });
        irohBridge = setup.bridge; walletPrimaryUri = setup.uri; iroh = setup.iroh;
      } else {
        const { startBridge } = require('../tools/chicory-iroh/bridge.cjs');
        const { createNodeIrohEndpoint } = require(path.join(source, 'dist/lightning/transport/iroh-node.js'));
        irohBridge = await startBridge({ identityPath: path.join(temp, 'iroh.key'), port,
          bindAddress: '127.0.0.1:0', discovery: false, relays: [] });
        walletPrimaryUri = providerKey + '@iroh:' + irohBridge.address().endpointId;
        iroh = { discovery: false, relays: [], factory: async options => {
          const endpoint = await createNodeIrohEndpoint({ ...options, discovery: false, relays: [] });
          const connect = endpoint.connect.bind(endpoint);
          endpoint.connect = (address, timeout) => {
            const primaryAddress = irohBridge.address();
            assert.equal(address.endpointId, primaryAddress.endpointId);
            return connect({ ...address, directAddresses: primaryAddress.directAddresses }, timeout);
          };
          return endpoint;
        } };
        evidence.scope = 'installed-chicory-portable-direct-iroh';
        evidence.irohEndpointId = irohBridge.address().endpointId;
      }
    }
    evidence.providerNodeId = providerKey;
    evidence.processes = [primary.child.pid];
    const endpoint = { host: electrum.hostname, port: Number(electrum.port), tls: electrum.protocol === 'ssl:' };
    payer = await BeignetNode.create({
      network: 'regtest', dataDir: path.join(temp, 'payer'), allowMultipleInstances: true,
      electrumHost: endpoint.host, electrumPort: endpoint.port, electrumTls: endpoint.tls,
      listenPort: await freePort(), autoBootstrap: false, autoGossipSync: false,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    const volume = makeVolume(path.join(temp, 'phone'));
    const databaseFactory = await createSqlJsDatabaseFactory({
      load: volume.read, save: volume.write, wasmBinary: fs.readFileSync(wasmFile),
    });
    let onionSocketFactory;
    if (fallbackTor && !iosHarness) {
      const { socks5SocketFactory } = require(path.join(source, 'dist/lightning/transport/peer-manager.js'));
      const [host, rawPort] = fallbackTor.proxy.split(':');
      onionSocketFactory = require('../tools/chicory-iroh/tor-socket.cjs').createTorSocketFactory({
        host: fallbackTor.host, port: fallbackTor.port,
        connect: socks5SocketFactory({ host, port: Number(rawPort) }, 20000),
      });
      evidence.irohFallback.hostOwnsOnionRouting = true;
    }
    // This implements the installed portable SocketFactory interface. It only
    // transports bytes; the unchanged engine performs Electrum and BOLT 8.
    const socketFactory = target => {
      if (onionSocketFactory && target.host === fallbackTor.host) {
        const socket = onionSocketFactory(target);
        sockets.add(socket); socket.once('close', () => sockets.delete(socket));
        return socket;
      }
      const isElectrum = target.host === endpoint.host && target.port === endpoint.port &&
        target.tls === endpoint.tls;
      const isPrimary = !irohBridge && target.host === '127.0.0.1' && target.port === port && !target.tls;
      assert.ok(isElectrum || isPrimary, 'Portable fixture refused an unexpected transport destination');
      const socket = target.tls ? tls.connect({ host: target.host, port: target.port }) :
        net.connect({ host: target.host, port: target.port });
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
      return socket;
    };
    let options = {
      volume, databaseFactory, socketFactory, electrum: endpoint,
      ...(iroh ? { iroh } : {}),
      nodeOptions: { logger: { debug() {}, info() {}, warn() {}, error() {} } },
      onDiagnostic: value => {
        diagnostics.push({ phase: String(value.phase).slice(0, 80), message: String(value.message).slice(0, 500) });
        if (diagnostics.length > 20) diagnostics.shift();
      },
    };
    runtime = await createPortableRuntime(options);
    client = new EmbeddedWalletClient({ runtime });
    const created = await client.createWallet({
      name: 'Native primary portable regtest', network: 'regtest',
      primaryUri: walletPrimaryUri, electrum: endpoint,
    });
    if (walletPrimaryFallbackUri) {
      // The installed public create API accepts only the primary URI. Persist
      // the same-key onion through the public settings operation before pairing.
      await client.updatePrimary(walletPrimaryUri, walletPrimaryFallbackUri);
      evidence.irohFallback.persistedUsingPublicSettings = true;
    }
    let walletId = created.id;
    rpc = (route, method = 'GET', body) => runtime.request({
      method, path: `/wallets/${walletId}/api${route}`, body,
    });
    await wait('installed wallet paired', async () => {
      const snapshot = await client.snapshot();
      return snapshot.primary.connected && snapshot.primary.setup === 'ready';
    });
    assert.equal((await rpc('/channels')).length, 0);
    pass('installed Chicory engine and wallet-core pair with native primary');

    if (process.env.CHICORY_TEST_INITIAL_DEPOSIT === '1') {
      const phoneNodeId = (await rpc('/info')).nodeId;
      const address = (await rpc('/address/new', 'POST', {})).address;
      assert.match(address, /^bcrt1/);
      btc('sendtoaddress', primary.ready.address, '0.02000000');
      const depositTxid = btc('sendtoaddress', address, '0.00030000');
      btc('-generate', '1');
      const candidate = await wait('first confirmed deposit opens a phone-funded home', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        return homes.length === 1 && homes[0].fundingTxid &&
          JSON.parse(btc('getrawmempool')).includes(homes[0].fundingTxid) && homes[0];
      });
      const transaction = JSON.parse(btc('getrawtransaction', candidate.fundingTxid, 'true'));
      assert.equal(transaction.confirmations || 0, 0);
      assert.ok(transaction.vin.some(input => input.txid === depositTxid));
      assert.equal(Math.round(transaction.vout[candidate.fundingOutputIndex].value * 1e8), candidate.capacitySats);
      const pending = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
      assert.equal(pending.length, 1);
      assert.equal(pending[0].isChannelReady, false);
      assert.equal(pending[0].isUsable, false);
      pass('first phone deposit creates one confirmed-only native funding candidate', {
        depositTxid, fundingTxid: candidate.fundingTxid, capacitySats: candidate.capacitySats,
      });
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);
      const restarted = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
      assert.equal(restarted?.fundingTxid, candidate.fundingTxid);
      assert.equal(restarted.isChannelReady, false);
      btc('-generate', '6');
      const funded = await wait('initial phone-funded home is usable on both engines', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
        return homes.length === 1 && homes[0].htlcUsable && homes[0].htlcCount === 0 &&
          native.length === 1 && native[0].isUsable && native[0].isChannelReady &&
          homes[0].fundingTxid === candidate.fundingTxid && native[0].fundingTxid === candidate.fundingTxid &&
          homes[0].capacitySats === native[0].valueSats && { home: homes[0], native: native[0] };
      });
      assert.ok(funded.home.localBalanceSats > 25000 && funded.home.localBalanceSats <= 30000);
      assert.equal((await client.snapshot()).balance.totalSats, funded.home.localBalanceSats);
      const invoice = await primary.request('invoice', { amountSats: 1000, description: 'Initial deposit channel spend' });
      const review = await client.prepareSend({ request: invoice.bolt11 });
      const sent = await client.send(review);
      assert.equal(sent.status, 'completed', sent.message || 'Initial deposit spend failed');
      const expectedBalance = funded.home.localBalanceSats - 1000;
      await wait('phone-funded spend commits', async () => {
        const home = (await rpc('/channels')).find(channel => channel.channelId === candidate.channelId);
        return home?.htlcUsable && home.htlcCount === 0 && home.localBalanceSats === expectedBalance;
      });
      pass('confirmed initial deposit home spends through native primary after primary restart', {
        fundingTxid: candidate.fundingTxid, capacitySats: funded.home.capacitySats,
        spentSats: 1000, localBalanceSats: expectedBalance,
      });
      await client.close();
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      await wait('initial deposit home survives phone reopen', async () => {
        await client.refreshWallet();
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        return (await client.snapshot()).primary.connected && homes.length === 1 && homes[0].htlcUsable &&
          homes[0].localBalanceSats === expectedBalance && homes[0].fundingTxid === candidate.fundingTxid;
      });
      assert.equal((await client.snapshot()).balance.totalSats, expectedBalance);
      pass('phone reopen preserves the initial deposit home and post-spend balance');
      succeeded = true;
      evidence.completedAt = new Date().toISOString();
      console.log('CHICORY_PORTABLE_INTEROP ' + JSON.stringify(evidence));
      return;
    }

    const payerAddress = await payer.getNewAddress();
    assert.match(payerAddress, /^bcrt1/);
    btc('sendtoaddress', primary.ready.address, '0.02000000');
    btc('sendtoaddress', payerAddress, '0.01000000');
    btc('-generate', '1');
    await wait('fixture funding visible', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return (await primary.request('balance')).spendableOnchainSats >= 1900000 &&
        payer.getBalance().onchain >= 1000000;
    });
    await payer.openChannel(providerKey, 400000, 0, 2, false, false);
    await wait('payer funding broadcast', () => {
      const txid = payer.listChannels().find(channel => channel.peerPubkey === providerKey && channel.fundingTxid)?.fundingTxid;
      return txid && JSON.parse(btc('getrawmempool')).includes(txid);
    });
    btc('-generate', '6');
    await wait('payer channel usable', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
    });
    pass('external payer has a confirmed channel to native primary');

    const quote = await client.quoteReceive({ amountSats: 20000, description: 'Installed Chicory JIT receive' });
    assert.equal(quote.feeSats, 120);
    assert.equal(quote.netSats, 19880);
    const receive = await client.receive(quote);
    assert.equal(receive.feeSats, 120);
    assert.match(receive.uri, /^bitcoin:bcrt1/);
    assert.match(receive.bolt11, /^lnbcrt/);
    assert.equal((await rpc('/channels')).length, 0);
    pass('installed wallet reviews and creates a skim-fee unified JIT request');

    const payment = await payer.payInvoiceSafe(receive.bolt11, timeoutMs, 1000);
    assert.equal(payment.status, 'COMPLETED', payment.failureDescription || 'Portable JIT payment failed');
    const settled = await wait('installed wallet Activity and committed balance settled', async () => {
      const snapshot = await client.snapshot();
      const activity = snapshot.activity.find(row => row.paymentHash === receive.paymentHash && row.status === 'completed');
      const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
      if (!activity || homes.length !== 1 || !homes[0].htlcUsable ||
          homes[0].htlcCount !== 0 || homes[0].localBalanceSats !== 19880 ||
          snapshot.balance.totalSats !== 19880 || snapshot.balance.availableSats <= 0 ||
          snapshot.balance.availableSats > 19880) return false;
      return { activity, homes, snapshot };
    });
    const { activity, homes, snapshot } = settled;
    assert.equal(homes.length, 1);
    assert.equal(homes[0].htlcUsable, true);
    assert.equal(homes[0].htlcCount, 0);
    assert.equal(homes[0].localBalanceSats, 19880);
    assert.equal(snapshot.balance.totalSats, 19880);
    assert.ok(snapshot.balance.availableSats > 0 && snapshot.balance.availableSats <= 19880);
    pass('installed wallet Activity and balances reflect the native JIT payment', {
      paymentHash: receive.paymentHash, status: activity.status,
      activityAmountSats: activity.amountSats, activityFeeSats: activity.feeSats,
      totalSats: snapshot.balance.totalSats, availableSats: snapshot.balance.availableSats,
    });

    // Persist and reopen the actual device engine, with its original keys and
    // database. This is process-local runtime recovery, not erased-phone recovery.
    await client.close();
    runtime = await createPortableRuntime(options);
    client = new EmbeddedWalletClient({ runtime, walletId });
    await client.startWallet();
    await wait('portable restart retains home and Activity', async () => {
      const current = await client.snapshot();
      return current.primary.connected && current.activity.some(row =>
        row.paymentHash === receive.paymentHash && row.status === 'completed') &&
        (await rpc('/channels')).some(channel => channel.htlcUsable);
    });
    assert.equal((await client.snapshot()).balance.totalSats, 19880);
    pass('installed wallet restart restores the paid request, balance and channel');

    const invoice = await primary.request('invoice', { amountSats: 3000, description: 'Portable outgoing payment' });
    const review = await wait('portable outbound route', () => client.prepareSend({ request: invoice.bolt11 }));
    const sent = await client.send(review);
    assert.equal(sent.status, 'completed', sent.message || 'Portable outgoing payment failed');
    const decoded = await rpc('/invoice/decode', 'POST', { bolt11: invoice.bolt11 });
    await wait('portable outgoing Activity settled', async () => (await client.snapshot()).activity.some(row =>
      row.paymentHash === decoded.paymentHash && row.kind === 'sent' && row.status === 'completed'));
    pass('installed wallet pays a native primary invoice and records completed Activity');

    if (process.env.CHICORY_TEST_RECOVERY === '1') {
      const mnemonic = await client.getRecoveryPhrase();
      const phoneNodeId = (await rpc('/info')).nodeId;
      const before = await wait('settled home before recovery import', async () => {
        const home = (await rpc('/channels')).find(channel => channel.peerPubkey === providerKey);
        return home?.htlcUsable && home.htlcCount === 0 && home.localBalanceSats === 16880 && home;
      });
      // Reopen the old installation once to publish its latest capsule, then
      // shut it down permanently. No two copies may sign channel updates.
      await client.close();
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      await wait('source installation reconnects to publish its latest capsule', async () =>
        (await client.snapshot()).primary.connected &&
        (await rpc('/channels')).some(channel => channel.htlcUsable && channel.localBalanceSats === 16880));
      await delay(1500);
      await client.close();
      await wait('old installation is fully stopped', () => sockets.size === 0);
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);

      const recoveredVolume = makeVolume(path.join(temp, 'recovered-phone'));
      const recoveredDatabase = await createSqlJsDatabaseFactory({
        load: recoveredVolume.read, save: recoveredVolume.write, wasmBinary: fs.readFileSync(wasmFile),
      });
      assert.deepEqual(recoveredVolume.list(), []);
      options = { ...options, volume: recoveredVolume, databaseFactory: recoveredDatabase };
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime });
      const recovered = await client.createWallet({
        name: 'Native primary recovery regtest', network: 'regtest',
        primaryUri: primary.ready.uri, electrum: endpoint, mnemonic, recoveryAutoApply: true,
      });
      walletId = recovered.id;
      const status = await wait('empty installation imports the primary capsule', async () => {
        const status = await client.getRecoveryStatus();
        if (status.autoApply.phase === 'refused') throw new Error('Recovery import refused: ' + status.autoApply.lastReason);
        return status.importComplete && status;
      });
      assert.equal(status.mode, 'peer-storage');
      pass('empty installed phone imports its peer-storage capsule after primary restart', {
        importComplete: status.importComplete, recoveryState: status.state,
      });
      await client.close();
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      const restored = await wait('recovered home retains the reference recency hold', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        const snapshot = await client.snapshot();
        const status = await client.getRecoveryStatus();
        return snapshot.primary.connected && homes.length === 1 && homes[0].state === 'NORMAL' &&
          homes[0].htlcUsable === false && homes[0].htlcCount === 0 &&
          homes[0].fundingTxid === before.fundingTxid && homes[0].localBalanceSats === before.localBalanceSats &&
          status.channels.some(channel => channel.channelId === before.channelId && channel.restoreRecencyUnproven) &&
          snapshot.balance.totalSats === before.localBalanceSats && { home: homes[0], snapshot, status };
      });
      assert.equal((await rpc('/info')).nodeId, phoneNodeId);
      // A compatible BOLT reestablish cannot prove this backup is the newest
      // state the primary holds. Beignet deliberately retains this hold. Never
      // weaken it in the test or ask the restored phone to force-close itself.
      assert.equal(restored.snapshot.balance.availableSats, 0);
      const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
      assert.equal(native.length, 1);
      assert.equal(native[0].fundingTxid, before.fundingTxid);
      assert.equal(native[0].valueSats, before.capacitySats);
      pass('recovered phone preserves the exact balance and permanent reference recency hold', {
        fundingTxid: restored.home.fundingTxid, recoveredBalanceSats: before.localBalanceSats,
        availableSats: restored.snapshot.balance.availableSats, htlcUsable: restored.home.htlcUsable,
        restoreRecencyUnproven: true,
      });
      if (process.env.CHICORY_TEST_RECOVERY_SWEEP === '1') {
        btc('-generate', '6');
        await primary.request('sync');
        await client.refreshWallet();
        await primary.request('force_close', { channelId: native[0].channelId });
        const commitment = await wait('primary broadcasts its current commitment for restored receiver', () => {
          const transactions = JSON.parse(btc('getrawmempool')).map(txid => JSON.parse(btc('getrawtransaction', txid, 'true')));
          return transactions.find(tx => tx.vin.some(input => input.txid === before.fundingTxid &&
            input.vout === before.fundingOutputIndex));
        });
        const receiverOutputs = commitment.vout.filter(output => Math.round(output.value * 1e8) === before.localBalanceSats);
        assert.equal(receiverOutputs.length, 1, 'Identify the restored receiver output without guessing a commitment index');
        const outputIndex = receiverOutputs[0].n;
        btc('-generate', '2');
        let minedAt = Date.now();
        const recoveredCoin = await wait('restored receiver sweeps its primary commitment output', async () => {
          if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
          await primary.request('sync');
          await client.refreshWallet();
          const coins = await rpc('/utxos');
          for (const coin of coins) {
            const tx = JSON.parse(btc('getrawtransaction', coin.txid, 'true'));
            if (tx.vin.some(input => input.txid === commitment.txid && input.vout === outputIndex)) {
              return { coin, transaction: tx };
            }
          }
          return false;
        });
        assert.equal(recoveredCoin.transaction.vin.length, 1);
        const paidSats = recoveredCoin.transaction.vout.reduce((sum, output) => sum + Math.round(output.value * 1e8), 0);
        const feeSats = before.localBalanceSats - paidSats;
        assert.ok(feeSats > 0 && paidSats > 0, 'The sweep must preserve the exact positive output after its measured fee');
        assert.equal(recoveredCoin.coin.valueSats, paidSats);
        assert.equal((await rpc('/balance')).onchain, paidSats);
        pass('restored phone sweeps the primary current commitment without signing stale state', {
          commitmentTxid: commitment.txid, outputIndex, sweepTxid: recoveredCoin.transaction.txid,
          restoredOutputSats: before.localBalanceSats, recoveredSats: paidSats, sweepFeeSats: feeSats,
        });
      }
    }

    if (process.env.CHICORY_TEST_JIT_SPLICE === '1') {
      // The first JIT channel spent the fixture's single confirmed coin. Its
      // change must confirm before the native wallet can select a splice input.
      btc('-generate', '6');
      await primary.request('sync');
      await client.refreshWallet();
      const before = await wait('settled home before JIT splice', async () => {
        const channels = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        const snapshot = await client.snapshot();
        return channels.length === 1 && channels[0].htlcUsable && channels[0].htlcCount === 0 &&
          channels[0].localBalanceSats === 16880 && snapshot.balance.totalSats === 16880 && channels[0];
      });
      const amountSats = 30000;
      const feeSats = 130;
      assert.ok(before.remoteBalanceSats < amountSats, 'This fixture requires a real outbound-liquidity shortage');
      assert.ok(before.capacitySats > amountSats, 'Keep the payment below the original negotiated HTLC maximum');
      const receiverNodeId = (await rpc('/info')).nodeId;
      const nativeBefore = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === receiverNodeId);
      assert.ok(nativeBefore?.isUsable);
      assert.equal(nativeBefore.fundingTxid, before.fundingTxid);
      const quote = await client.quoteReceive({ amountSats, description: 'Installed Chicory existing-home JIT splice' });
      assert.equal(quote.feeSats, feeSats);
      assert.equal(quote.netSats, amountSats - feeSats);
      const receive = await client.receive(quote);
      assert.equal(receive.feeSats, feeSats);
      assert.match(receive.bolt11, /^lnbcrt/);
      const dispatched = [];
      const manager = payer.getNode().getChannelManager();
      const originalAdd = manager.addHtlc;
      manager.addHtlc = function (...args) {
        if (Buffer.isBuffer(args[2]) && args[2].toString('hex') === receive.paymentHash) {
          dispatched.push({ amountMsat: String(args[1]) });
        }
        return originalAdd.apply(this, args);
      };
      let outcome;
      let minedAt = Date.now();
      const pendingPayment = payer.payInvoiceSafe(receive.bolt11, timeoutMs, 1000)
        .then(result => { outcome = { result }; }, error => { outcome = { error }; });
      try {
        await wait('single incoming payment triggers native JIT splice', async () => {
          if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
          await primary.request('sync');
          await client.refreshWallet();
          return outcome;
        });
        await pendingPayment;
        if (outcome.error) throw outcome.error;
        assert.equal(outcome.result.status, 'COMPLETED', outcome.result.failureDescription || 'Existing-home JIT failed');
      } finally {
        manager.addHtlc = originalAdd;
      }
      assert.equal(dispatched.length, 1, 'A retried or multipart payment does not qualify this single-shortage path');
      // The payer's first hop also pays the primary's advertised routing fee.
      // The exact receiver amount and single JIT charge are asserted below.
      assert.ok(BigInt(dispatched[0].amountMsat) >= BigInt(amountSats * 1000));
      const expectedBalance = before.localBalanceSats + amountSats - feeSats;
      const settled = await wait('installed wallet and native primary agree on JIT splice', async () => {
        if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
        await primary.request('sync');
        await client.refreshWallet();
        const channels = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
        const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === receiverNodeId);
        const snapshot = await client.snapshot();
        const activity = snapshot.activity.find(row => row.paymentHash === receive.paymentHash && row.status === 'completed');
        return channels.length === 1 && channels[0].htlcUsable && channels[0].htlcCount === 0 &&
          channels[0].localBalanceSats === expectedBalance && channels[0].fundingTxid !== before.fundingTxid &&
          native.length === 1 && native[0].isUsable && native[0].isChannelReady &&
          native[0].fundingTxid === channels[0].fundingTxid && native[0].valueSats === channels[0].capacitySats &&
          snapshot.balance.totalSats === expectedBalance && activity && { current: channels[0], native: native[0], activity };
      });
      assert.equal(settled.current.channelId, before.channelId);
      assert.equal(settled.native.channelId, nativeBefore.channelId);
      assert.equal(settled.native.fundingOutputIndex, settled.current.fundingOutputIndex);
      assert.ok(settled.current.capacitySats > before.capacitySats);
      const transaction = JSON.parse(btc('getrawtransaction', settled.current.fundingTxid, 'true'));
      assert.ok(transaction.vin.some(input => input.txid === before.fundingTxid && input.vout === before.fundingOutputIndex));
      assert.equal(Math.round(transaction.vout[settled.current.fundingOutputIndex].value * 1e8), settled.current.capacitySats);
      pass('installed wallet receives through one enlarged home with one JIT splice fee', {
        paymentHash: receive.paymentHash, amountSats, feeSats, netReceivedSats: amountSats - feeSats,
        localBalanceSats: settled.current.localBalanceSats, activityAmountSats: settled.activity.amountSats,
        oldFundingTxid: before.fundingTxid, fundingTxid: settled.current.fundingTxid,
        oldCapacitySats: before.capacitySats, capacitySats: settled.current.capacitySats,
        receiverChannels: 1, dispatchedParts: dispatched.length, primaryUsable: settled.native.isUsable,
        incomingAmountMsat: dispatched[0].amountMsat,
      });
    }

    if (process.env.CHICORY_TEST_OFFLINE === '1') {
      // Current Chicory requires an existing home with 50,000 sats beyond the
      // fixed voucher amount. Fund that capacity explicitly through the native
      // wallet. This is fixture setup, not an automatic offline funding policy.
      btc('-generate', '6');
      await primary.request('sync');
      await client.refreshWallet();
      const phoneNodeId = (await rpc('/info')).nodeId;
      const nativeBefore = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
      assert.ok(nativeBefore?.isUsable);
      await primary.request('splice_in', { channelId: nativeBefore.channelId, amountSats: 100000 });
      let minedAt = Date.now();
      await wait('native home has offline reservation capacity', async () => {
        if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
        await primary.request('sync');
        await client.refreshWallet();
        const home = (await rpc('/channels')).find(channel => channel.peerPubkey === providerKey);
        const native = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
        return home?.htlcUsable && home.htlcCount === 0 && home.remoteBalanceSats > 55000 &&
          native?.isUsable && home.fundingTxid === native.fundingTxid &&
          native.valueSats === nativeBefore.valueSats + 100000;
      });
      if (irohBridge || process.env.CHICORY_TEST_IOS === '1') evidence.irohOfflineSetupDelayMs = 0;
      let before = (await client.snapshot()).balance.totalSats;
      const amountSats = 5000;
      const quote = await client.quoteReceive({ amountSats, mode: 'offline', description: 'Installed Chicory offline receive' });
      assert.equal(quote.mode, 'offline');
      assert.equal(quote.concurrentVersion, 2);
      assert.equal(quote.feeSats, 0);
      assert.equal(quote.netSats, amountSats);
      const receive = await client.receive(quote);
      assert.equal(receive.offlineReceive, true);
      assert.match(receive.bolt11, /^lnbcrt/);
      const epochs = await rpc('/ffor/epochs');
      const home = (await rpc('/channels')).find(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
      const epoch = epochs.find(item => item.state === 'ACTIVE' && item.role === 'R' &&
        item.peerNodeId === providerKey && item.channelId === home?.channelId &&
        item.slots.some(slot => slot.paymentHash === receive.paymentHash));
      assert.ok(epoch, 'The invoice must have an activated native reservation');
      assert.equal(epoch.concurrentVersion, 2);
      assert.equal(epoch.slots.length, 1);
      assert.equal(epoch.slots[0].amountMsat, String(amountSats * 1000));
      assert.equal(epoch.capabilityHold, false);
      assert.equal(epoch.activationMismatch, false);
      pass('installed wallet prepares an active concurrent-v2 offline reservation', {
        channelId: epoch.channelId, epochId: epoch.epochId, amountSats,
        paymentHash: receive.paymentHash,
      });

      if (unpaidOffline) {
        // Reserved v2 vouchers cannot be failed offchain when an unpaid book
        // closes. Stop admission through the real API, then prove the pending
        // voucher and the absence of a credit survive both process restarts.
        const pauseId = 'unpaid-retirement-' + randomBytes(12).toString('hex');
        assert.equal((await rpc('/channelize/pause', 'POST', { paused: true, requestId: pauseId })).paused, true);
        const noUnpaidCredit = async () => {
          const snapshot = await client.snapshot();
          assert.equal(snapshot.activity.filter(row => row.paymentHash === receive.paymentHash &&
            row.status === 'completed').length, 0, 'An unpaid voucher must not create a completed receive');
          return snapshot;
        };
        if (autoExpireOffline) {
          // The installed runtime polls its coordinator every two seconds and
          // closes admission at invoice expiry plus a two-minute grace period.
          // Use the actual signed invoice time and real wall clock. This mode
          // never calls the explicit close route or changes the engine clock.
          const decoded = await rpc('/invoice/decode', 'POST', { bolt11: receive.bolt11 });
          const invoiceExpirySeconds = Number(decoded.expiry);
          const invoiceExpiresAt = (Number(decoded.timestamp) + invoiceExpirySeconds) * 1000;
          const automaticCloseAt = invoiceExpiresAt + 120000;
          const startedWaitingAt = Date.now();
          const deadline = automaticCloseAt + 60000;
          assert.equal(invoiceExpirySeconds, 600);
          assert.ok(Number.isSafeInteger(invoiceExpiresAt) && invoiceExpiresAt > startedWaitingAt);
          assert.ok(deadline - startedWaitingAt <= 780000, 'Bound the real-clock expiry wait to thirteen minutes');
          evidence.offlineCloseMode = 'automatic-wall-clock-expiry';
          console.log('WAIT automatic offline expiry and grace: up to ' +
            Math.ceil((deadline - startedWaitingAt) / 1000) + ' real seconds');
          let observedGrace = false;
          let observedCloseAt;
          while (Date.now() < deadline) {
            const current = await rpc('/ffor/epoch?channelId=' + epoch.channelId);
            const channel = (await rpc('/channels')).find(item => item.channelId === epoch.channelId);
            const snapshot = await noUnpaidCredit();
            const now = Date.now();
            assert.equal(current.epochId, epoch.epochId);
            assert.equal(channel?.htlcCount, 1);
            assert.equal(channel.localBalanceSats, before);
            assert.equal(snapshot.balance.totalSats, before);
            if (current.state === 'DRAINING') {
              assert.ok(now >= automaticCloseAt, 'Automatic admission close must preserve the full invoice grace');
              observedCloseAt = now;
              break;
            }
            assert.equal(current.state, 'ACTIVE', 'An unpaid reservation must stay active until automatic admission close');
            if (now >= invoiceExpiresAt && now < automaticCloseAt && !observedGrace) {
              observedGrace = true;
              pass('real invoice expiry preserves the unpaid voucher during the automatic-close grace', {
                epochId: epoch.epochId, invoiceExpirySeconds, graceSeconds: 120,
                reservedHtlcs: channel.htlcCount, completedReceiveRows: 0,
              });
            }
            await delay(2000);
          }
          assert.ok(observedGrace, 'Observe the live grace period rather than only its final state');
          assert.ok(observedCloseAt, 'Installed automatic admission close did not finish within its bounded grace');
          pass('unchanged installed runtime automatically closes admission after real invoice expiry and grace', {
            epochId: epoch.epochId, invoiceExpirySeconds, graceSeconds: 120,
            waitedMs: observedCloseAt - startedWaitingAt,
            closeDelayAfterGraceMs: observedCloseAt - automaticCloseAt,
          });
        } else {
          evidence.offlineCloseMode = 'explicit-admission-close';
          await rpc('/ffor/epoch/close', 'POST', { channelId: epoch.channelId });
        }
        const draining = async () => {
          await primary.request('sync');
          await client.refreshWallet();
          const book = await rpc('/ffor/epoch?channelId=' + epoch.channelId);
          const current = (await rpc('/channels')).find(channel => channel.channelId === epoch.channelId);
          const snapshot = await noUnpaidCredit();
          return snapshot.primary.connected && book.state === 'DRAINING' && book.epochId === epoch.epochId &&
            book.slots.length === 1 && book.slots[0].state === 'unsettled' &&
            current?.htlcCount === 1 && current.localBalanceSats === before &&
            snapshot.balance.totalSats === before && { book, current };
        };
        await wait('unpaid v2 close keeps its reserved voucher without credit', draining);
        pass((autoExpireOffline ? 'automatic' : 'explicit') + ' unpaid epoch close stops admission and retains the reserved voucher', {
          channelId: epoch.channelId, epochId: epoch.epochId, state: 'DRAINING', reservedHtlcs: 1,
        });
        await client.close();
        await wait('phone sockets close before unpaid restart', () => sockets.size === 0);
        await primary.stop();
        primary = await startPrimary(path.join(temp, 'primary'), port);
        evidence.processes.push(primary.child.pid);
        assert.equal(primary.ready.nodeId, providerKey);
        runtime = await createPortableRuntime(options);
        client = new EmbeddedWalletClient({ runtime, walletId });
        await client.startWallet();
        const preserved = await wait('unpaid reservation survives phone and primary restart', draining);
        assert.equal((await rpc('/channelize/status')).paused, true);
        pass('both restarts preserve the unpaid reserved book without a false credit', {
          epochId: preserved.book.epochId, localBalanceSats: preserved.current.localBalanceSats,
          reservedHtlcs: preserved.current.htlcCount,
        });

        // Confirm the current splice before the public primary force-close.
        // Match the actual funding spend and exact voucher output on chain.
        btc('-generate', '6');
        await primary.request('sync');
        await client.refreshWallet();
        await primary.request('force_close', { channelId: epoch.channelId });
        const commitment = await wait('primary broadcasts the unpaid reserved commitment', () => {
          const transactions = JSON.parse(btc('getrawmempool')).map(txid => JSON.parse(btc('getrawtransaction', txid, 'true')));
          return transactions.find(tx => tx.vin.some(input => input.txid === preserved.current.fundingTxid &&
            input.vout === preserved.current.fundingOutputIndex));
        });
        const voucherOutputs = commitment.vout.filter(output => Math.round(output.value * 1e8) === amountSats);
        assert.equal(voucherOutputs.length, 1, 'Identify the exact reserved voucher without guessing its output index');
        const voucherIndex = voucherOutputs[0].n;
        btc('-generate', '1');
        await primary.request('sync');
        await client.refreshWallet();
        assert.ok(Number.isSafeInteger(epoch.voucherExpiry) && epoch.voucherExpiry > epoch.settlementDeadline);
        const height = Number(btc('getblockcount'));
        const advance = Math.max(0, epoch.voucherExpiry + 1 - height);
        assert.ok(advance <= 1500, 'Bound the regtest-only timeout advancement');
        if (advance) btc('-generate', String(advance));
        const scannedBlocks = new Map();
        const timeout = await wait('native wallet broadcasts or confirms the real voucher timeout', async () => {
          await primary.request('sync');
          await client.refreshWallet();
          await noUnpaidCredit();
          const transactions = JSON.parse(btc('getrawmempool')).map(txid => JSON.parse(btc('getrawtransaction', txid, 'true')));
          const tip = Number(btc('getblockcount'));
          for (let blockHeight = epoch.voucherExpiry; blockHeight <= tip; blockHeight++) {
            const hash = btc('getblockhash', String(blockHeight));
            if (!scannedBlocks.has(hash)) scannedBlocks.set(hash, JSON.parse(btc('getblock', hash, '2')).tx);
            transactions.push(...scannedBlocks.get(hash));
          }
          return transactions.find(tx => tx.locktime === epoch.voucherExpiry &&
            tx.vin.some(input => input.txid === commitment.txid && input.vout === voucherIndex));
        });
        btc('-generate', '6');
        await primary.request('sync');
        await client.refreshWallet();
        const confirmedTimeout = JSON.parse(btc('getrawtransaction', timeout.txid, 'true'));
        assert.ok(confirmedTimeout.confirmations >= 6);
        const unspentVoucher = btc('gettxout', commitment.txid, String(voucherIndex), 'true');
        assert.ok(unspentVoucher === '' || unspentVoucher === 'null');
        await noUnpaidCredit();
        assert.ok(!(await primary.request('channels')).some(channel => channel.channelId === epoch.channelId));
        pass('unpaid reserved voucher resolves through its actual six-confirmation timeout', {
          commitmentTxid: commitment.txid, voucherOutputIndex: voucherIndex,
          timeoutTxid: timeout.txid, voucherExpiry: epoch.voucherExpiry,
          timeoutConfirmations: confirmedTimeout.confirmations, completedReceiveRows: 0,
        });

        // Restart after chain resolution too. A new home is a new channel;
        // reserved v2 does not claim that an unpaid book can reopen its old one.
        await client.close();
        await wait('phone sockets close after unpaid timeout', () => sockets.size === 0);
        await primary.stop();
        primary = await startPrimary(path.join(temp, 'primary'), port);
        evidence.processes.push(primary.child.pid);
        assert.equal(primary.ready.nodeId, providerKey);
        runtime = await createPortableRuntime(options);
        client = new EmbeddedWalletClient({ runtime, walletId });
        await client.startWallet();
        await wait('phone reconnects after durable unpaid timeout', async () => {
          await primary.request('sync');
          await client.refreshWallet();
          return (await noUnpaidCredit()).primary.connected;
        });
        await payer.connectPeer(providerKey, '127.0.0.1', port);
        await wait('payer reestablishes before fresh-home JIT', async () => {
          await payer.refreshWallet();
          return payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
        });
        const freshQuote = await client.quoteReceive({ amountSats: 10000, description: 'Fresh home after unpaid reservation timeout' });
        const freshReceive = await client.receive(freshQuote);
        const freshPayment = await payer.payInvoiceSafe(freshReceive.bolt11, timeoutMs, 1000);
        assert.equal(freshPayment.status, 'COMPLETED', freshPayment.failureDescription || 'Fresh-home JIT failed');
        const fresh = await wait('installed phone has one fresh usable JIT home after timeout', async () => {
          await client.refreshWallet();
          const snapshot = await noUnpaidCredit();
          const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
          const rows = snapshot.activity.filter(row => row.paymentHash === freshReceive.paymentHash && row.status === 'completed');
          return homes.length === 1 && homes[0].channelId !== epoch.channelId && homes[0].htlcCount === 0 &&
            homes[0].localBalanceSats === freshQuote.netSats && rows.length === 1 && { home: homes[0], rows };
        });
        pass('durable unpaid timeout permits a fresh native JIT home with no old invoice credit', {
          oldChannelId: epoch.channelId, channelId: fresh.home.channelId,
          localBalanceSats: fresh.home.localBalanceSats, freshReceiveRows: fresh.rows.length,
          unpaidReceiveRows: 0,
        });
        await rpc('/channelize/pause', 'POST', { paused: false, requestId: pauseId });
      } else {
        if (process.env.CHICORY_TEST_OFFLINE_CONCURRENT === '1') {
          const outgoing = await primary.request('invoice', { amountSats: 1000, description: 'Ordinary spend while offline voucher is reserved' });
          const review = await client.prepareSend({ request: outgoing.bolt11 });
          const sent = await client.send(review);
          assert.equal(sent.status, 'completed', sent.message || 'Active reservation must allow ordinary payments');
          await wait('ordinary outgoing commitment preserves the reserved voucher', async () => {
            const current = (await rpc('/channels')).find(channel => channel.channelId === epoch.channelId);
            return current?.htlcUsable && current.htlcCount === 1 && current.localBalanceSats === before - 1000;
          });
          const incoming = await rpc('/invoice/create', 'POST', {
            amountSats: 1200, description: 'Ordinary receive while offline voucher is reserved', expirySecs: 600,
          });
          await primary.request('pay', { bolt11: incoming.bolt11 });
          await wait('ordinary incoming commitment preserves the active reservation', async () => {
            await client.refreshWallet();
            const current = (await rpc('/channels')).find(channel => channel.channelId === epoch.channelId);
            const book = (await rpc('/ffor/epochs')).find(item => item.epochId === epoch.epochId);
            return current?.htlcUsable && current.htlcCount === 1 && current.localBalanceSats === before + 200 &&
              book?.state === 'ACTIVE' && !book.capabilityHold && !book.activationMismatch;
          });
          before += 200;
          assert.equal((await client.snapshot()).balance.totalSats, before);
          pass('native active offline reservation survives ordinary payments in both directions', {
            channelId: epoch.channelId, epochId: epoch.epochId,
            sentSats: 1000, receivedSats: 1200, totalSats: before,
          });
        }

        await client.close();
        await wait('phone sockets close before offline payment', () => sockets.size === 0);
        await primary.stop();
        primary = await startPrimary(path.join(temp, 'primary'), port);
        evidence.processes.push(primary.child.pid);
        assert.equal(primary.ready.nodeId, providerKey);
        await payer.connectPeer(providerKey, '127.0.0.1', port);
        await wait('payer reestablishes after offline primary restart', async () => {
          await primary.request('sync');
          await payer.refreshWallet();
          return payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
        });
        assert.equal((await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId)?.isUsable, false);
        const paid = await payer.payInvoiceSafe(receive.bolt11, timeoutMs, 1000);
        assert.equal(paid.status, 'COMPLETED', paid.failureDescription || 'Offline delegated payment failed');
        assert.equal(sockets.size, 0, 'The phone must remain disconnected throughout settlement');
        pass('restarted native primary settles the external payment while the phone is stopped', {
          amountSats, paymentHash: receive.paymentHash,
        });

        // Restart after settlement as well, before allowing the receiver to read
        // its receipt. The receipt and upstream claim must both survive this.
        await primary.stop();
        primary = await startPrimary(path.join(temp, 'primary'), port);
        evidence.processes.push(primary.child.pid);
        assert.equal(primary.ready.nodeId, providerKey);
        const reopen = async () => {
          runtime = await createPortableRuntime(options);
          client = new EmbeddedWalletClient({ runtime, walletId });
          await client.startWallet();
          return wait('offline receipt is credited exactly once after reopen', async () => {
            await client.refreshWallet();
            const snapshot = await client.snapshot();
            const rows = snapshot.activity.filter(row => row.paymentHash === receive.paymentHash && row.status === 'completed');
            const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
            return snapshot.primary.connected && snapshot.balance.totalSats === before + amountSats &&
              rows.length === 1 && homes.length === 1 && homes[0].htlcUsable && homes[0].htlcCount === 0 &&
              homes[0].localBalanceSats === before + amountSats && { snapshot, rows, home: homes[0] };
          });
        };
        const first = await reopen();
        assert.equal(first.rows[0].amountSats, amountSats);
        pass('installed phone recovers the durable offline receipt after primary restart', {
          amountSats, totalSats: first.snapshot.balance.totalSats, activityRows: first.rows.length,
        });
        await client.close();
        const second = await reopen();
        assert.equal(second.rows[0].amountSats, amountSats);
        pass('second phone reopen preserves one offline credit and one completed Activity row', {
          totalSats: second.snapshot.balance.totalSats, activityRows: second.rows.length,
        });
      }
    }

    if (process.env.CHICORY_TEST_SPLICES === '1') {
      const before = (await rpc('/channels')).find(channel => channel.htlcUsable);
      assert.ok(before);
      const phoneNodeId = (await rpc('/info')).nodeId;
      assert.match(phoneNodeId, /^0[23][0-9a-f]{64}$/);
      const nativeBefore = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
      assert.ok(nativeBefore);
      assert.match(nativeBefore.fundingTxid || '', /^[0-9a-f]{64}$/, 'Rebuild the example with funding outpoint fields');
      assert.equal(nativeBefore.fundingTxid, before.fundingTxid);
      const assertOldFunding = async () => {
        const channels = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
        assert.equal(channels.length, 1);
        assert.equal(channels[0].channelId, nativeBefore.channelId);
        assert.equal(channels[0].fundingTxid, nativeBefore.fundingTxid, 'Unconfirmed peer funding must not replace active funding');
        assert.equal(channels[0].fundingOutputIndex, nativeBefore.fundingOutputIndex);
        assert.equal(channels[0].valueSats, nativeBefore.valueSats, 'Unconfirmed peer contribution must not increase active channel value');
      };
      const address = (await rpc('/address/new', 'POST', {})).address;
      assert.match(address, /^bcrt1/);
      const depositTxid = btc('sendtoaddress', address, '0.00030000');
      btc('-generate', '1');

      // Confirm the deposit coin, then stop mining before its splice broadcasts.
      // An immediate mining loop would hide accidental inheritance of the
      // original provider-funded channel's zero-conf trust.
      const candidateTxid = await wait('portable deposit splice candidate in mempool', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const home = (await rpc('/channels')).find(channel => channel.channelId === before.channelId);
        const candidate = home?.pendingSpliceTxid ||
          (home?.fundingTxid !== before.fundingTxid ? home?.fundingTxid : null);
        return candidate && JSON.parse(btc('getrawmempool')).includes(candidate) && candidate;
      });
      const candidate = JSON.parse(btc('getrawtransaction', candidateTxid, 'true'));
      assert.equal(candidate.confirmations || 0, 0);
      assert.ok(candidate.vin.some(input => input.txid === depositTxid));
      assert.ok(candidate.vin.some(input => input.txid === nativeBefore.fundingTxid && input.vout === nativeBefore.fundingOutputIndex));
      for (let sample = 0; sample < 3; sample++) {
        await primary.request('sync');
        await client.refreshWallet();
        await assertOldFunding();
        await delay(500);
      }
      pass('native primary retains original funding while peer deposit splice is unconfirmed', { candidateTxid });

      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);
      await payer.connectPeer(providerKey, '127.0.0.1', port);
      await wait('phone reconnects after pending-splice provider restart', async () => {
        await client.refreshWallet();
        return (await client.snapshot()).primary.connected;
      });
      await primary.request('sync');
      assert.equal(JSON.parse(btc('getrawtransaction', candidateTxid, 'true')).confirmations || 0, 0);
      await assertOldFunding();
      pass('provider restart preserves the unconfirmed peer splice confirmation requirement', { candidateTxid });

      btc('-generate', '5');
      assert.equal(JSON.parse(btc('getrawtransaction', candidateTxid, 'true')).confirmations, 5);
      for (let sample = 0; sample < 3; sample++) {
        await primary.request('sync');
        await client.refreshWallet();
        await assertOldFunding();
        await delay(500);
      }
      pass('native primary retains original funding below its six-confirmation inbound splice floor', { candidateTxid, confirmations: 5 });
      btc('-generate', '1');
      assert.equal(JSON.parse(btc('getrawtransaction', candidateTxid, 'true')).confirmations, 6);
      await wait('portable deposit splice-in after six confirmations', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const channels = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey);
        const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
        return channels.length === 1 && channels[0].htlcUsable && channels[0].state === 'NORMAL' &&
          channels[0].capacitySats >= before.capacitySats + 25000 && channels[0].fundingTxid === candidateTxid &&
          native.length === 1 && native[0].fundingTxid === candidateTxid && native[0].valueSats === channels[0].capacitySats;
      });
      pass('installed wallet channelizes a confirmed deposit into its existing home at the required depth', {
        candidateTxid, confirmations: 6,
      });

      let minedAt = Date.now();
      const mine = () => {
        if (Date.now() - minedAt >= 5000) { btc('-generate', '1'); minedAt = Date.now(); }
      };
      const destination = btc('getnewaddress', 'chicory-portable-splice', 'bech32');
      const spliceReview = await client.prepareSend({ request: destination, amountSats: 2000 });
      const splice = await client.send(spliceReview);
      assert.ok(['pending', 'completed'].includes(splice.status), splice.message);
      const row = await wait('portable splice-out chain proof', async () => {
        mine();
        await primary.request('sync');
        await client.refreshWallet();
        return (await client.snapshot()).activity.find(item => item.address === destination && item.status === 'completed' && item.txid);
      });
      const transaction = JSON.parse(btc('getrawtransaction', row.txid, 'true'));
      assert.ok(transaction.confirmations >= 1);
      assert.ok(transaction.vout.some(output => output.scriptPubKey.address === destination && Math.round(output.value * 1e8) === 2000));
      pass('installed wallet splice-out pays the exact destination amount', { txid: row.txid, amountSats: 2000 });
    }

    if (process.env.CHICORY_TEST_CONFLICT === '1') {
      btc('-generate', '6');
      await primary.request('sync');
      await client.refreshWallet();
      const phoneNodeId = (await rpc('/info')).nodeId;
      const before = (await rpc('/channels')).find(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
      assert.ok(before && !before.pendingSpliceTxid);
      const amountSats = 5000;
      const quote = await client.quoteReceive({ amountSats, description: 'Disposable conflicted direct funding' });
      const request = await client.receive(quote);
      const phone = startDirectFundingPayer(path.join(temp, 'conflicting-payer'),
        primary.ready.uri, request.uri, amountSats, true);
      let conflict;
      try {
        await wait('direct-funding candidate before conflicting spend', async () => {
          if (phone.state.error) throw phone.state.error;
          await primary.request('sync');
          await client.refreshWallet();
          return phone.state.exited && phone.state.steps.conflict;
        });
        if (phone.state.error) throw phone.state.error;
        conflict = phone.state.steps.conflict;
      } finally { await phone.stop(); }
      assert.ok(conflict);
      const candidate = JSON.parse(btc('getrawtransaction', conflict.candidateTxid, 'true'));
      assert.equal(candidate.confirmations || 0, 0);
      assert.ok(candidate.vin.some(input => input.txid === before.fundingTxid && input.vout === before.fundingOutputIndex));
      assert.equal(candidate.vin[conflict.inputIndex].txid, conflict.spentTxid);
      assert.equal(candidate.vin[conflict.inputIndex].vout, conflict.spentVout);
      assert.notEqual(conflict.spentTxid, before.fundingTxid);
      const conflictTxid = btc('sendrawtransaction', conflict.transaction);
      const competing = JSON.parse(btc('getrawtransaction', conflictTxid, 'true'));
      assert.equal(competing.vin.length, 1);
      assert.equal(competing.vin[0].txid, conflict.spentTxid);
      assert.equal(competing.vin[0].vout, conflict.spentVout);
      assert.ok(!competing.vin.some(input => input.txid === before.fundingTxid));
      pass('disposable payer replaces only its nonshared direct-funding input', {
        candidateTxid: conflict.candidateTxid, conflictTxid, inputIndex: conflict.inputIndex,
        oldFundingTxid: before.fundingTxid, replacementFeeSats: 10000,
      });
      btc('-generate', '5');
      await primary.request('sync');
      await client.refreshWallet();
      assert.equal(JSON.parse(btc('getrawtransaction', conflictTxid, 'true')).confirmations, 5);
      const retained = (await rpc('/channels')).find(channel => channel.channelId === before.channelId);
      assert.equal(retained.pendingSpliceTxid, conflict.candidateTxid);
      assert.equal(retained.localBalanceSats, before.localBalanceSats);
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      await wait('phone reconnects to primary with unconfirmed candidate retained', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const home = (await rpc('/channels')).find(channel => channel.channelId === before.channelId);
        const native = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
        return (await client.snapshot()).primary.connected && home?.pendingSpliceTxid === conflict.candidateTxid &&
          native?.fundingTxid === before.fundingTxid;
      });
      pass('five-confirmation conflict does not roll back the candidate across primary restart', {
        candidateTxid: conflict.candidateTxid, conflictTxid, confirmations: 5,
      });
      btc('-generate', '1');
      const recovered = await wait('both peers durably retire the proven conflicted candidate', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const home = (await rpc('/channels')).find(channel => channel.channelId === before.channelId);
        const native = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
        return home?.htlcUsable && !home.pendingSpliceTxid && home.fundingTxid === before.fundingTxid &&
          home.localBalanceSats === before.localBalanceSats && home.capacitySats === before.capacitySats &&
          native?.isUsable && native.fundingTxid === before.fundingTxid && native.valueSats === before.capacitySats && home;
      });
      pass('six-confirmation conflict restores matching usable prior funding on both peers', {
        candidateTxid: conflict.candidateTxid, conflictTxid, confirmations: 6,
        fundingTxid: recovered.fundingTxid, localBalanceSats: recovered.localBalanceSats,
      });
      await client.close();
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      await wait('restored prior funding survives both restarts', async () => {
        const home = (await rpc('/channels')).find(channel => channel.channelId === before.channelId);
        const native = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === phoneNodeId);
        return home?.htlcUsable && !home.pendingSpliceTxid && home.fundingTxid === before.fundingTxid &&
          native?.isUsable && native.fundingTxid === before.fundingTxid;
      });
      const invoice = await primary.request('invoice', { amountSats: 1000, description: 'Spend after conflict recovery' });
      const review = await client.prepareSend({ request: invoice.bolt11 });
      const payment = await client.send(review);
      assert.equal(payment.status, 'completed', payment.message || 'Recovered channel must accept ordinary payments');
      pass('installed wallet spends from recovered prior funding after both restarts', { amountSats: 1000 });
    }

    if (process.env.CHICORY_TEST_DIRECT_FUNDING === '1') {
      const testDirectFunding = async (label, amountSats, before) => {
        const receiveQuote = await client.quoteReceive({ amountSats, description: 'Installed direct funding ' + label });
        const request = await client.receive(receiveQuote);
        assert.ok(new URL(request.uri).searchParams.get('bgnq'), 'The real wallet request must advertise direct funding');
        const phone = startDirectFundingPayer(path.join(temp, 'direct-payer-' + label),
          primary.ready.uri, request.uri, amountSats);
        let minedAt = Date.now();
        try {
          await wait('installed direct-funding payer ' + label, async () => {
            if (phone.state.error) return true;
            if (Date.now() - minedAt >= 3000) {
              btc('-generate', '1');
              minedAt = Date.now();
            }
            await primary.request('sync');
            await client.refreshWallet();
            return phone.state.exited && phone.state.steps.proof;
          });
          if (phone.state.error) throw phone.state.error;
          const proof = phone.state.steps.proof;
          assert.equal(proof.amountSats, amountSats);
          assert.equal(proof.receiptVerified, true);
          assert.equal(proof.activityStatus, 'completed');
          assert.equal(proof.activityAmountSats, amountSats);
          const current = await wait('direct funding changes exactly one home ' + label, async () => {
            if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
            await primary.request('sync');
            await client.refreshWallet();
            const channels = (await rpc('/channels')).filter(channel =>
              channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
            return channels.length === 1 && channels[0].state === 'NORMAL' && channels[0].htlcUsable &&
              channels[0].fundingTxid === proof.fundingTxid && channels[0];
          });
          assert.equal(current.fundingOutputIndex, proof.fundingOutputIndex);
          assert.equal(current.capacitySats, (before?.capacitySats || 0) + amountSats);
          assert.equal(current.localBalanceSats, (before?.localBalanceSats || 0) + amountSats);
          const native = await wait('native primary activates direct funding ' + label, async () => {
            if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
            await primary.request('sync');
            await client.refreshWallet();
            const channels = (await primary.request('channels')).filter(channel =>
              channel.counterpartyNodeId === proof.receiverNodeId);
            return channels.length === 1 && channels[0].isChannelReady && channels[0].isUsable &&
              channels[0].fundingTxid === proof.fundingTxid && channels[0];
          });
          assert.equal(native.fundingOutputIndex, proof.fundingOutputIndex);
          assert.equal(native.valueSats, current.capacitySats);
          const transaction = JSON.parse(btc('getrawtransaction', proof.fundingTxid, 'true'));
          assert.ok(transaction.confirmations >= 1);
          assert.ok(transaction.vin.some(input => input.txid === proof.spentTxid && input.vout === proof.spentVout));
          if (before) assert.ok(transaction.vin.some(input =>
            input.txid === before.fundingTxid && input.vout === before.fundingOutputIndex));
          const output = transaction.vout[proof.fundingOutputIndex];
          assert.equal(output.scriptPubKey.hex, proof.fundingScript);
          assert.equal(Math.round(output.value * 1e8), current.capacitySats);
          const received = await runtime.request({ path: `/api/wallets/${walletId}` });
          assert.ok(['accepted', 'completed'].includes(received.lfbw?.lastOffer?.state));
          pass('installed direct funding ' + label + ' pays the exact channel amount and verifies its receipt', {
            ...proof, capacitySats: current.capacitySats, localBalanceSats: current.localBalanceSats,
            payerCoinSats: phone.state.steps.coin.valueSats, primaryUsable: native.isUsable,
            confirmations: transaction.confirmations,
          });
          const spendInvoice = await primary.request('invoice', {
            amountSats: 1000, description: 'Spend direct funding ' + label,
          });
          const spendReview = await client.prepareSend({ request: spendInvoice.bolt11 });
          const spend = await client.send(spendReview);
          assert.equal(spend.status, 'completed', spend.message || 'Direct-funded channel payment failed');
          await wait('direct-funded channel commits outgoing payment ' + label, async () => {
            const channels = (await rpc('/channels')).filter(channel =>
              channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
            return channels.length === 1 && channels[0].htlcCount === 0 &&
              channels[0].localBalanceSats === current.localBalanceSats - 1000;
          });
          pass('installed wallet spends from the direct-funded ' + label + ' channel', { amountSats: 1000 });
        } finally { await phone.stop(); }
      };

      const existing = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
      assert.equal(existing.length, 1);
      assert.equal(existing[0].htlcUsable, true);
      // Keep the existing home's quote inside its remaining inbound capacity.
      // The payer still uses an actual confirmed 20,000-sat coin, below the
      // installed wallet's 25,000-sat automatic channelization floor.
      if (process.env.CHICORY_DF_ONLY_FRESH === '1') {
        evidence.directFundingScope = 'initial-channel-only';
        console.log('SKIP existing-home direct funding: diagnostic fresh-channel scope');
      } else {
        evidence.directFundingScope = 'existing-home-and-initial-channel';
        await testDirectFunding('existing-home', 5000, existing[0]);
      }

      await client.close();
      const freshVolume = makeVolume(path.join(temp, 'direct-receiver-new'));
      const freshDatabase = await createSqlJsDatabaseFactory({
        load: freshVolume.read, save: freshVolume.write, wasmBinary: fs.readFileSync(wasmFile),
      });
      options = { ...options, volume: freshVolume, databaseFactory: freshDatabase };
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime });
      walletId = (await client.createWallet({
        name: 'Installed new direct-funding receiver', network: 'regtest',
        primaryUri: primary.ready.uri, electrum: endpoint,
      })).id;
      await wait('new direct-funding receiver paired', async () => {
        const current = await client.snapshot();
        return current.primary.connected && current.primary.setup === 'ready';
      });
      assert.equal((await rpc('/channels')).length, 0);
      await testDirectFunding('initial-channel', 15000, null);
    }
    if (process.env.CHICORY_TEST_SEND_MAX) {
      const kind = process.env.CHICORY_TEST_SEND_MAX;
      assert.ok(['bech32', 'bech32m', 'p2wsh'].includes(kind));
      btc('-generate', '6');
      await primary.request('sync');
      await client.refreshWallet();
      const before = (await rpc('/channels')).find(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
      assert.ok(before);
      const phoneNodeId = (await rpc('/info')).nodeId;
      const bitcoin = require(require.resolve('bitcoinjs-lib', { paths: [source] }));
      const destination = kind === 'p2wsh' ? bitcoin.payments.p2wsh({
        redeem: { output: Buffer.from([bitcoin.opcodes.OP_TRUE]) }, network: bitcoin.networks.regtest,
      }).address : btc('getnewaddress', 'chicory-send-max', kind);
      const maximum = await client.quoteMax({ request: destination });
      const review = await client.prepareSend({ request: destination, max: true });
      assert.equal(review.amountSats, maximum.amountSats);
      assert.ok(review.amountSats > 0);
      const outcome = await client.send(review);
      assert.ok(['pending', 'completed'].includes(outcome.status), outcome.message);
      let minedAt = Date.now();
      const paid = await wait('send-max pays the reviewed output and preserves one usable home', async () => {
        if (Date.now() - minedAt >= 3000) { btc('-generate', '1'); minedAt = Date.now(); }
        await primary.request('sync');
        await client.refreshWallet();
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
        const rows = (await client.snapshot()).activity.filter(row => row.address === destination && row.status === 'completed');
        const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
        return homes.length === 1 && homes[0].htlcUsable && homes[0].fundingTxid !== before.fundingTxid &&
          native.length === 1 && native[0].isUsable && native[0].fundingTxid === homes[0].fundingTxid &&
          native[0].valueSats === homes[0].capacitySats && homes[0].htlcCount === 0 &&
          rows.length === 1 && rows[0].txid && { home: homes[0], row: rows[0] };
      });
      assert.equal(paid.home.channelId, before.channelId);
      assert.equal(paid.home.localBalanceSats, review.keptSats);
      const transaction = JSON.parse(btc('getrawtransaction', paid.row.txid, 'true'));
      assert.ok(transaction.confirmations >= 1);
      assert.ok(transaction.vin.some(input => input.txid === before.fundingTxid && input.vout === before.fundingOutputIndex));
      const script = Buffer.from(bitcoin.address.toOutputScript(destination, bitcoin.networks.regtest)).toString('hex');
      const paidSats = transaction.vout.filter(output => output.scriptPubKey.hex === script)
        .reduce((total, output) => total + Math.round(output.value * 1e8), 0);
      assert.equal(paidSats, review.amountSats);
      pass('installed send-max pays the exact reviewed ' + kind + ' destination', {
        amountSats: paidSats, keptSats: review.keptSats, txid: paid.row.txid,
      });
      await client.close();
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      await wait('send-max is restored once after phone and primary restart', async () => {
        await client.refreshWallet();
        const snapshot = await client.snapshot();
        const rows = snapshot.activity.filter(row => row.txid === paid.row.txid);
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
        const native = (await primary.request('channels')).filter(channel => channel.counterpartyNodeId === phoneNodeId);
        return snapshot.primary.connected && rows.length === 1 && rows[0].status === 'completed' &&
          native.length === 1 && native[0].isUsable && native[0].fundingTxid === paid.home.fundingTxid &&
          homes.length === 1 && homes[0].htlcUsable && homes[0].localBalanceSats === review.keptSats;
      });
      pass('installed send-max retains one completed Activity row and its home after both restarts');
    }
    if (process.env.CHICORY_TEST_DRAIN === '1') {
      btc('-generate', '6');
      await primary.request('sync');
      await client.refreshWallet();
      const coinAddress = (await rpc('/address/new', 'POST', {})).address;
      const coinTxid = btc('sendtoaddress', coinAddress, '0.00020000');
      btc('-generate', '1');
      await wait('drain fixture loose coin is confirmed below channelization floor', async () => {
        await client.refreshWallet();
        return (await rpc('/utxos')).some(coin => coin.txid === coinTxid && coin.height > 0);
      });
      const address = btc('getnewaddress', 'chicory-drain', 'bech32m');
      const review = await client.prepareDrain({ address });
      assert.ok(review.drain.closeAmountSats > 0 && review.drain.sweepAmountSats > 0);
      const result = await client.send(review);
      assert.ok(['pending', 'completed'].includes(result.status), result.message);
      const submitted = await wait('both drain transactions broadcast without confirmation', async () => {
        await primary.request('sync');
        const progress = await client.getDrain(review.id);
        return progress.phase === 'pending' && new Set(progress.txids).size === 2 && progress;
      });
      for (const txid of submitted.txids) {
        const tx = JSON.parse(btc('getrawtransaction', txid, 'true'));
        assert.equal(tx.confirmations || 0, 0);
        assert.ok(tx.vout.some(output => output.scriptPubKey.address === address));
      }
      assert.equal((await rpc('/channelize/status')).paused, false);
      pass('installed drain broadcasts cooperative close and loose-coin sweep before confirmation', {
        txids: submitted.txids, reviewedAmountSats: review.amountSats,
      });
      const laterTxid = btc('sendtoaddress', coinAddress, '0.00001000');
      await client.close();
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);
      await payer.connectPeer(providerKey, '127.0.0.1', port);
      runtime = await createPortableRuntime(options);
      client = new EmbeddedWalletClient({ runtime, walletId });
      await client.startWallet();
      await wait('drained phone reconnects before old close confirmations', async () => {
        await client.refreshWallet();
        return (await client.snapshot()).primary.connected &&
          payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
      });
      assert.equal((await rpc('/channelize/status')).paused, false);
      const quote = await client.quoteReceive({ amountSats: 5000, description: 'Receive after pending drain' });
      const receive = await client.receive(quote);
      const paid = await payer.payInvoiceSafe(receive.bolt11, timeoutMs, 1000);
      assert.equal(paid.status, 'COMPLETED', paid.failureDescription || 'Post-drain JIT failed');
      await wait('post-drain receive commits on a fresh home', async () => {
        const homes = (await rpc('/channels')).filter(channel => channel.peerPubkey === providerKey && channel.state !== 'CLOSED');
        return homes.length === 1 && homes[0].htlcUsable && homes[0].htlcCount === 0 && homes[0].localBalanceSats === quote.netSats;
      });
      for (const txid of submitted.txids) assert.equal(JSON.parse(btc('getrawtransaction', txid, 'true')).confirmations || 0, 0);
      pass('restarted installed wallet receives through a new home while old drain confirmations remain pending', {
        paymentHash: receive.paymentHash, netReceivedSats: quote.netSats,
      });
      btc('-generate', '6');
      const completed = await wait('drain completion preserves one Activity row and later coin', async () => {
        await primary.request('sync');
        await client.refreshWallet();
        const progress = await client.getDrain(review.id);
        const rows = (await client.snapshot()).activity.filter(row => row.drain?.requestId === review.id);
        const utxos = await rpc('/utxos');
        return progress.phase === 'completed' && rows.length === 1 && rows[0].status === 'completed' &&
          utxos.some(coin => coin.txid === laterTxid && coin.valueSats === 1000) &&
          !utxos.some(coin => coin.txid === coinTxid) && { progress, row: rows[0] };
      });
      assert.deepEqual(new Set(completed.progress.txids), new Set(submitted.txids));
      for (const txid of submitted.txids) {
        const tx = JSON.parse(btc('getrawtransaction', txid, 'true'));
        assert.ok(!tx.vin.some(input => input.txid === laterTxid));
      }
      pass('installed drain completes once after both restarts and excludes later receipts', {
        txids: completed.progress.txids, laterCoinSats: 1000,
      });
    }
    succeeded = true;
    evidence.completedAt = new Date().toISOString();
    console.log('CHICORY_PORTABLE_INTEROP ' + JSON.stringify(evidence));
  } catch (error) {
    console.error('FAIL ' + error.message);
    if (rpc) {
      try {
        console.error('PORTABLE_CHANNELS ' + JSON.stringify((await rpc('/channels')).map(channel => ({
          channelId: channel.channelId, peerPubkey: channel.peerPubkey, state: channel.state,
          localBalanceSats: channel.localBalanceSats, remoteBalanceSats: channel.remoteBalanceSats,
          capacitySats: channel.capacitySats, htlcCount: channel.htlcCount, htlcUsable: channel.htlcUsable,
          fundingTxid: channel.fundingTxid, fundingOutputIndex: channel.fundingOutputIndex,
          pendingSpliceTxid: channel.pendingSpliceTxid, fforState: channel.ffor?.state,
        }))));
        console.error('PORTABLE_BALANCE ' + JSON.stringify(await rpc('/balance')));
        if (process.env.CHICORY_TEST_OFFLINE === '1') {
          // Never log the complete epoch, voucher, receipt, or wallet record.
          // Only public identities and lifecycle flags help diagnose a stall.
          console.error('PORTABLE_OFFLINE_STATES ' + JSON.stringify((await rpc('/ffor/epochs')).map(epoch => ({
            channelId: epoch.channelId, epochId: epoch.epochId, role: epoch.role,
            state: epoch.state, capabilityHold: epoch.capabilityHold,
            activationMismatch: epoch.activationMismatch, concurrentVersion: epoch.concurrentVersion,
            slots: (epoch.slots || []).map(slot => ({ k: slot.k, state: slot.state,
              redeemed: slot.redeemed, fulfilled: slot.fulfilled, removed: slot.removed })),
          }))));
        }
      } catch { /* Startup or shutdown may have failed. */ }
    }
    console.error('PORTABLE_DIAGNOSTICS ' + JSON.stringify(diagnostics));
    console.error('Retained disposable regtest state at ' + temp);
    throw error;
  } finally {
    if (runtime) await runtime.close().catch(() => {});
    for (const socket of sockets) socket.destroy();
    if (payer) await payer.gracefulShutdown(5000).catch(() => {});
    if (primary) await primary.stop();
    if (iosHarness) await iosHarness.close();
    if (irohBridge) await irohBridge.close();
    if (fallbackTor) {
      await Promise.all(fallbackEndpoints.map(endpoint => endpoint.close()));
      await fallbackTor.close();
      if (!iosHarness) {
        assert(evidence.irohFallback.attempts > 0);
        assert.equal(evidence.irohFallback.unexpectedIrohConnections, 0, 'Fallback qualification used Iroh');
      }
    }
    if (process.env.BEIGNET_EVIDENCE_FILE) fs.writeFileSync(process.env.BEIGNET_EVIDENCE_FILE,
      JSON.stringify({ ...evidence, passed: succeeded }, null, 2) + '\n', { mode: 0o600 });
    if (succeeded && process.env.CHICORY_KEEP_TEST_STATE !== '1') fs.rmSync(temp, { recursive: true, force: true });
  }
}

const run = process.argv[2] === '--direct-funding-payer' ? directFundingPayer : main;
run().catch(error => {
  console.error('PORTABLE_INTEROP_ERROR ' + error.message);
  process.exitCode = 1;
});
