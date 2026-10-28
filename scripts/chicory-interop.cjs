#!/usr/bin/env node
'use strict';

// Funded regtest qualification of the native JIT subset. This does not qualify
// direct funding, restored-wallet recovery, Iroh, or full parity.
// Build first: cargo build --features chicory --example chicory-primary
// Run: BEIGNET_SOURCE_DIR=/path/to/built/beignet node scripts/chicory-interop.cjs
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
const evidence = { scope: 'native-jit-subset', checks: [] };

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

async function captureAuthorization(receiver, primaryKey, makeInvoice, decodeAck) {
  const wire = receiver.getNode();
  const send = wire.sendCustomMessage;
  let payload;
  let ack;
  wire.sendCustomMessage = function (peer, subtype, body) {
    if (peer === primaryKey && subtype === 1) payload = Buffer.from(body);
    return send.call(this, peer, subtype, body);
  };
  const receive = message => {
    if (message.peerPubkey === primaryKey && message.subtype === 2 && payload) {
      const candidate = decodeAck(message.payload);
      if (candidate.requestId.equals(payload.subarray(32, 40))) ack = candidate;
    }
  };
  wire.on('custom-message', receive);
  try {
    const invoice = await makeInvoice();
    assert.ok(payload && ack && ack.accepted, 'Accepted authorization was not captured');
    return { invoice, payload, ack };
  } finally {
    wire.sendCustomMessage = send;
    wire.removeListener('custom-message', receive);
  }
}

function replayAuthorization(receiver, primaryKey, payload, decodeAck) {
  const wire = receiver.getNode();
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      clearTimeout(timer);
      wire.removeListener('custom-message', receive);
      if (error) reject(error); else resolve(result);
    };
    const receive = message => {
      if (message.peerPubkey !== primaryKey || message.subtype !== 2) return;
      try {
        const ack = decodeAck(message.payload);
        if (ack.requestId.equals(payload.subarray(32, 40))) finish(null, ack);
      } catch (error) { finish(error); }
    };
    const timer = setTimeout(() => finish(new Error('Authorization replay timed out')), 20000);
    wire.on('custom-message', receive);
    try { wire.sendCustomMessage(primaryKey, 1, payload); }
    catch (error) { finish(error); }
  });
}

function customExchange(client, peer, subtype, decode, send) {
  const wire = client.getNode();
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      clearTimeout(timer);
      wire.removeListener('custom-message', receive);
      if (error) reject(error); else resolve(result);
    };
    const receive = message => {
      if (message.peerPubkey !== peer || message.subtype !== subtype) return;
      try { finish(null, decode(message.payload)); }
      catch (error) { finish(error); }
    };
    const timer = setTimeout(() => finish(new Error(`Custom subtype ${subtype} timed out`)), 15000);
    wire.on('custom-message', receive);
    try { send(); } catch (error) { finish(error); }
  });
}

function storageRetrieval(client, peer) {
  const wire = client.getNode();
  let timer;
  let receive;
  const cancel = () => {
    clearTimeout(timer);
    wire.removeListener('peer_storage:retrieved', receive);
  };
  const promise = new Promise((resolve, reject) => {
    receive = (sender, bytes) => {
      if (sender !== peer) return;
      cancel();
      resolve(Buffer.from(bytes));
    };
    timer = setTimeout(() => {
      cancel();
      reject(new Error('Padded peer-storage retrieval timed out'));
    }, timeoutMs);
    wire.on('peer_storage:retrieved', receive);
  });
  // A stop or reconnect can fail before this promise is awaited. Its original
  // rejection still reaches the awaiting test while cleanup removes the listener.
  promise.catch(() => {});
  return { promise, cancel };
}

async function main() {
  assert.ok(['tcp:', 'ssl:'].includes(electrum.protocol), 'Use a TCP or TLS Electrum URL');
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 30000 && timeoutMs <= 600000);
  assert.ok(fs.existsSync(binary), 'Build the chicory-primary Rust example first');
  const chain = JSON.parse(btc('getblockchaininfo'));
  assert.equal(chain.chain, 'regtest', 'Refusing to fund any network except regtest');
  evidence.chain = chain.chain;
  evidence.primaryChainSource = primaryChainSource.startsWith('rpc:') ? 'bitcoin-core-rpc' : 'electrum';
  console.log('Primary chain source: ' + evidence.primaryChainSource);
  evidence.startedAt = new Date().toISOString();
  evidence.beignetVersion = require(path.join(source, 'package.json')).version;
  const { BeignetNode } = require(path.join(source, 'dist/cli/beignet-node.js'));
  const { decodeJitAck } = require(path.join(source, 'dist/lightning/liquidity/jit-receive.js'));
  const { encodeDfRelayFrame, decodeDfRelayFrame } =
    require(path.join(source, 'dist/lightning/direct-funding/messages.js'));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ldk-chicory-interop-'));
  const port = await freePort();
  let primary;
  let payer;
  let receiver;
  let succeeded = false;
  const createClient = async name => BeignetNode.create({
    network: 'regtest', dataDir: path.join(temp, name), allowMultipleInstances: true,
    electrumHost: electrum.hostname, electrumPort: Number(electrum.port),
    electrumTls: electrum.protocol === 'ssl:', listenPort: await freePort(),
    autoBootstrap: false, autoGossipSync: false,
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  try {
    primary = await startPrimary(path.join(temp, 'primary'), port);
    payer = await createClient('payer');
    receiver = await createClient('receiver');
    const providerKey = primary.ready.nodeId;
    evidence.providerNodeId = providerKey;
    evidence.processes = [primary.child.pid];
    assert.equal(receiver.listChannels().length, 0);
    receiver.addTrustedPeer(providerKey);
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    await receiver.connectPeer(providerKey, '127.0.0.1', port);
    pass('both Beignet clients complete BOLT 8 with native primary');

    // Synthetic opaque bytes test relay transport only. They are deliberately
    // not a direct-funding offer and cannot authorize or sign a transaction.
    const relayPayload = randomBytes(128);
    const forwarded = await customExchange(receiver, providerKey, 22, decodeDfRelayFrame, () =>
      payer.getNode().sendCustomMessage(providerKey, 22, encodeDfRelayFrame({
        to: Buffer.from(receiver.getInfo().nodeId, 'hex'), subtype: 16, payload: relayPayload,
      })));
    assert.equal(forwarded.from?.toString('hex'), payer.getInfo().nodeId);
    assert.equal(forwarded.to, undefined);
    assert.equal(forwarded.subtype, 16);
    assert.deepEqual(forwarded.payload, relayPayload);
    pass('native relay preserves opaque bytes and stamps authenticated sender');

    const payerAddress = await payer.getNewAddress();
    assert.match(payerAddress, /^bcrt1/);
    btc('sendtoaddress', primary.ready.address, '0.02000000');
    btc('sendtoaddress', payerAddress, '0.01000000');
    btc('-generate', '1');
    await wait('funding visible', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return (await primary.request('balance')).spendableOnchainSats >= 1900000 &&
        payer.getBalance().onchain >= 1000000;
    });
    pass('isolated primary and payer funded on regtest');

    await payer.openChannel(providerKey, 400000, 0, 2, false, false);
    await wait('payer funding broadcast', () => {
      const fundingTxid = payer.listChannels().find(channel =>
        channel.peerPubkey === providerKey && channel.fundingTxid)?.fundingTxid;
      return fundingTxid && JSON.parse(btc('getrawmempool')).includes(fundingTxid);
    });
    btc('-generate', '6');
    await wait('payer channel usable', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
    });
    pass('confirmed payer channel established');

    const quote = await receiver.getJitQuote({
      lspPubkey: providerKey, amountSats: 20000, targetRemainingInboundSat: 10000,
    });
    assert.equal(quote.accepted, true, quote.reason || 'JIT quote refused');
    assert.equal(quote.withinCeilings, true);
    assert.equal(quote.flatFeeSat, 100);
    assert.equal(quote.feePpm, 1000);
    assert.equal(quote.feeSats, 120);
    assert.equal(receiver.listChannels().length, 0);
    pass('Beignet JIT quote agrees on a 120 sat skim fee', { feeSats: quote.feeSats });

    const excessive = await receiver.getJitQuote({
      lspPubkey: providerKey, amountSats: 1000000, targetRemainingInboundSat: 10000,
    });
    assert.equal(excessive.accepted, false, 'Over-budget request must be refused');
    pass('excessive JIT request refused before funding');

    const captured = await captureAuthorization(receiver, providerKey, () => receiver.createJitInvoice({
      lspPubkey: providerKey, amountSats: 20000, description: 'Native primary JIT regtest',
      expirySecs: 600, targetRemainingInboundSat: 10000, feeMode: 'skim',
      maxFlatFeeSat: quote.flatFeeSat, maxFeePpm: quote.feePpm,
    }), decodeJitAck);
    assert.equal(captured.invoice.feeMode, 'skim');
    assert.equal(receiver.listChannels().length, 0, 'Authorization must not pre-fund a channel');
    pass('unchanged Beignet client creates a JIT invoice');

    await primary.stop();
    primary = await startPrimary(path.join(temp, 'primary'), port);
    evidence.processes.push(primary.child.pid);
    assert.equal(primary.ready.nodeId, providerKey);
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    await receiver.connectPeer(providerKey, '127.0.0.1', port);
    const replay = await replayAuthorization(receiver, providerKey, captured.payload, decodeJitAck);
    assert.equal(replay.accepted, true, replay.reason || 'Persisted authorization refused');
    assert.deepEqual(replay.interceptScid, captured.ack.interceptScid);
    assert.equal(replay.flatFeeSat, captured.ack.flatFeeSat);
    assert.equal(replay.feePpm, captured.ack.feePpm);
    assert.equal(replay.feeMode, captured.ack.feeMode);
    await wait('payer channel reestablished', () =>
      payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable));
    pass('provider restart retains identity and idempotent authorization');

    const payment = await payer.payInvoiceSafe(captured.invoice.bolt11, timeoutMs, 1000);
    assert.equal(payment.status, 'COMPLETED', payment.failureDescription || 'JIT payment did not complete');
    const received = await wait('receiver committed payment', () => {
      const value = receiver.getPayment(captured.invoice.paymentHash);
      return value?.status === 'COMPLETED' ? value : null;
    });
    // Beignet currently reports the gross invoice amount in this record.
    // Verify credited funds against committed channel balances instead.
    // https://github.com/coreyphillips/beignet/issues/1869
    assert.equal(received.amountSats, 20000);
    const homes = await wait('receiver committed channel balance', () => {
      const channels = receiver.listChannels().filter(channel => channel.peerPubkey === providerKey);
      return channels.length === 1 && channels[0].htlcCount === 0 &&
        channels[0].localBalanceSats === 19880 ? channels : null;
    });
    assert.equal(homes.length, 1);
    assert.equal(homes[0].htlcUsable, true);
    assert.equal(homes[0].localBalanceSats, 19880);
    pass('payer payment opens receiver channel and settles after restart', {
      paymentHash: captured.invoice.paymentHash, receivedSats: homes[0].localBalanceSats,
      reportedPaymentSats: received.amountSats,
      feeSats: quote.feeSats, receiverChannels: homes.length,
    });

    // Beignet adds its 8-byte bPS1 header and pads this to exactly 65531 bytes.
    // The test checks opaque provider persistence, not wallet restoration.
    const backup = randomBytes(65523);
    assert.ok(receiver.getNode().distributePeerStorage(backup) >= 1);
    // Same authenticated stream: the quote response is a processing barrier
    // after the preceding peer_storage frame, which has no protocol ACK.
    await receiver.getJitQuote({
      lspPubkey: providerKey, amountSats: 1000, targetRemainingInboundSat: 0,
    });
    let retrieval = storageRetrieval(receiver, providerKey);
    try {
      receiver.disconnectPeer(providerKey);
      await wait('receiver reconnect', async () => {
        await receiver.connectPeer(providerKey, '127.0.0.1', port);
        return true;
      });
      assert.deepEqual(await retrieval.promise, backup);
    } finally {
      retrieval.cancel();
    }
    pass('65531-byte padded peer backup roundtrips on reconnect', { wireBytes: 65531 });

    retrieval = storageRetrieval(receiver, providerKey);
    try {
      await primary.stop();
      primary = await startPrimary(path.join(temp, 'primary'), port);
      evidence.processes.push(primary.child.pid);
      assert.equal(primary.ready.nodeId, providerKey);
      await receiver.connectPeer(providerKey, '127.0.0.1', port);
      assert.deepEqual(await retrieval.promise, backup);
    } finally {
      retrieval.cancel();
    }
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    await wait('receiver home reestablished after storage restart', () =>
      receiver.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable));
    pass('65531-byte padded peer backup and channel survive provider restart', { wireBytes: 65531 });
    evidence.completedAt = new Date().toISOString();
    succeeded = true;
    console.log('CHICORY_INTEROP ' + JSON.stringify(evidence));
  } catch (error) {
    console.error('FAIL ' + error.message);
    if (primary) {
      try { console.error('PRIMARY_CHANNELS ' + JSON.stringify(await primary.request('channels'))); }
      catch { /* A stopped primary can be the failure under test. */ }
    }
    if (payer) console.error('PAYER_CHANNELS ' + JSON.stringify(payer.listChannels()));
    if (receiver) console.error('RECEIVER_CHANNELS ' + JSON.stringify(receiver.listChannels()));
    console.error('Retained disposable regtest state at ' + temp);
    throw error;
  } finally {
    if (receiver) await receiver.gracefulShutdown(5000).catch(() => {});
    if (payer) await payer.gracefulShutdown(5000).catch(() => {});
    if (primary) await primary.stop();
    if (process.env.BEIGNET_EVIDENCE_FILE) {
      fs.writeFileSync(process.env.BEIGNET_EVIDENCE_FILE,
        JSON.stringify({ ...evidence, passed: succeeded }, null, 2) + '\n', { mode: 0o600 });
    }
    if (succeeded && process.env.CHICORY_KEEP_TEST_STATE !== '1') {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  }
}

main().catch(error => {
  console.error('INTEROP_ERROR ' + error.message);
  process.exitCode = 1;
});
