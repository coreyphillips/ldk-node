#!/usr/bin/env node
'use strict';

// Funded two-part JIT qualification through an unchanged Beignet receiver.
// Uses the existing Beignet MPP sender with explicit routes, without package edits.
// Build first: cargo build --features chicory --example chicory-primary
// Run: BEIGNET_SOURCE_DIR=/path/to/built/beignet node scripts/chicory-mpp-interop.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const readline = require('node:readline');
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
const evidence = { scope: 'native-jit-two-part', checks: [] };
const existingHome = process.env.CHICORY_MPP_EXISTING_HOME === '1';
const amountSats = existingHome ? 30000 : 20000;
const feeSats = 100 + amountSats / 1000;
const partMsat = BigInt(amountSats * 500);

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


function forwardedProof(message) {
  const number = field => {
    const found = new RegExp('\\b' + field + ': (?:Some\\((\\d+)\\)|None)').exec(message);
    assert.ok(found, 'Native forwarding event omitted ' + field);
    return found[1] === undefined ? 0 : Number(found[1]);
  };
  assert.ok(message.includes('claim_from_onchain_tx: false'));
  return {
    feeMsat: number('total_fee_earned_msat'),
    skimMsat: number('skimmed_fee_msat'),
    forwardedMsat: number('outbound_amount_forwarded_msat'),
  };
}

async function main() {
  assert.ok(['tcp:', 'ssl:'].includes(electrum.protocol));
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 30000 && timeoutMs <= 600000);
  assert.ok(fs.existsSync(binary), 'Build the chicory-primary Rust example first');
  assert.equal(JSON.parse(btc('getblockchaininfo')).chain, 'regtest', 'Refusing to fund outside regtest');
  const { BeignetNode } = require(path.join(source, 'dist/cli/beignet-node.js'));
  const { decodeJitAck } = require(path.join(source, 'dist/lightning/liquidity/jit-receive.js'));
  const { decode } = require(path.join(source, 'dist/lightning/invoice/decode.js'));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ldk-chicory-mpp-'));
  const port = await freePort();
  evidence.startedAt = new Date().toISOString();
  evidence.chain = 'regtest';
  evidence.beignetVersion = require(path.join(source, 'package.json')).version;
  let primary;
  let payer;
  let receiver;
  let succeeded = false;
  let restoreObserver;
  const createClient = async name => BeignetNode.create({
    network: 'regtest', dataDir: path.join(temp, name), allowMultipleInstances: true,
    electrumHost: electrum.hostname, electrumPort: Number(electrum.port), electrumTls: electrum.protocol === 'ssl:',
    listenPort: await freePort(), autoBootstrap: false, autoGossipSync: false,
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  try {
    primary = await startPrimary(path.join(temp, 'primary'), port);
    payer = await createClient('payer');
    receiver = await createClient('receiver');
    const providerKey = primary.ready.nodeId;
    const receiverKey = receiver.getInfo().nodeId;
    evidence.providerNodeId = providerKey;
    evidence.processes = [primary.child.pid];
    receiver.addTrustedPeer(providerKey);
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    await receiver.connectPeer(providerKey, '127.0.0.1', port);
    assert.equal(receiver.listChannels().length, 0);
    const address = await payer.getNewAddress();
    assert.match(address, /^bcrt1/);
    btc('sendtoaddress', primary.ready.address, '0.02000000');
    btc('sendtoaddress', address, '0.01000000');
    btc('-generate', '1');
    await wait('fixture funds visible', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return (await primary.request('balance')).spendableOnchainSats >= 1900000 && payer.getBalance().onchain >= 1000000;
    });
    await payer.openChannel(providerKey, 400000, 0, 2, false, false);
    await wait('payer funding broadcast', () => {
      const txid = payer.listChannels().find(channel => channel.peerPubkey === providerKey)?.fundingTxid;
      return txid && JSON.parse(btc('getrawmempool')).includes(txid);
    });
    btc('-generate', '6');
    await wait('payer channel usable', async () => {
      await primary.request('sync');
      await payer.refreshWallet();
      return payer.listChannels().some(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
    });
    pass('native primary has a confirmed external payer channel and an unfunded receiver');

    let priorHome;
    if (existingHome) {
      const initialQuote = await receiver.getJitQuote({ lspPubkey: providerKey, amountSats: 20000, targetRemainingInboundSat: 10000 });
      const initial = await receiver.createJitInvoice({ lspPubkey: providerKey, amountSats: 20000,
        description: 'Existing home for multipart splice', expirySecs: 600,
        targetRemainingInboundSat: 10000, feeMode: 'skim',
        maxFlatFeeSat: initialQuote.flatFeeSat, maxFeePpm: initialQuote.feePpm });
      const paid = await payer.payInvoiceSafe(initial.bolt11, timeoutMs, 1000);
      assert.equal(paid.status, 'COMPLETED', paid.failureDescription);
      await wait('settled initial home', () => receiver.listChannels().some(channel =>
        channel.htlcUsable && channel.htlcCount === 0 && channel.localBalanceSats === 19880));
      const direct = receiver.createInvoice(8000, 'Reduce existing home inbound capacity');
      await primary.request('pay', { bolt11: direct.bolt11 });
      priorHome = await wait('settled initial home before multipart splice', () => {
        const channels = receiver.listChannels().filter(channel => channel.peerPubkey === providerKey);
        return channels.length === 1 && channels[0].htlcUsable && channels[0].htlcCount === 0 &&
          channels[0].localBalanceSats === 27880 && channels[0];
      });
      assert.ok(priorHome.remoteBalanceSats < Number(partMsat / 1000n));
      btc('-generate', '6');
      await primary.request('sync');
      await receiver.refreshWallet();
      pass('existing home has insufficient liquidity for either multipart contribution', {
        fundingTxid: priorHome.fundingTxid, capacitySats: priorHome.capacitySats,
        remoteBalanceSats: priorHome.remoteBalanceSats, partSats: Number(partMsat / 1000n),
      });
    }
    const quote = await receiver.getJitQuote({ lspPubkey: providerKey, amountSats, targetRemainingInboundSat: 10000 });
    assert.equal(quote.accepted, true, quote.reason);
    assert.equal(quote.feeSats, feeSats);
    const captured = await captureAuthorization(receiver, providerKey, () => receiver.createJitInvoice({
      lspPubkey: providerKey, amountSats, description: 'Native primary two-part JIT receive',
      expirySecs: 600, targetRemainingInboundSat: 10000, feeMode: 'skim',
      maxFlatFeeSat: quote.flatFeeSat, maxFeePpm: quote.feePpm,
    }), decodeJitAck);
    assert.equal(captured.invoice.feeMode, 'skim');
    const invoice = decode(captured.invoice.bolt11);
    assert.equal(invoice.amountMsat, BigInt(amountSats * 1000));
    assert.equal(invoice.paymentHash.toString('hex'), captured.invoice.paymentHash);
    assert.ok(invoice.paymentSecret);
    const hint = invoice.routingHints?.flat().find(hop => existingHome ? hop.pubkey.toString('hex') === providerKey :
      hop.shortChannelId.equals(captured.ack.interceptScid));
    assert.ok(hint, 'Invoice must route through the primary');
    assert.equal(hint.pubkey.toString('hex'), providerKey);
    if (!existingHome) {
      assert.equal(hint.feeBaseMsat, 0);
      assert.equal(hint.feeProportionalMillionths, 0);
    }
    assert.equal(receiver.listChannels().length, existingHome ? 1 : 0);
    await primary.stop();
    primary = await startPrimary(path.join(temp, 'primary'), port);
    evidence.processes.push(primary.child.pid);
    assert.equal(primary.ready.nodeId, providerKey);
    await payer.connectPeer(providerKey, '127.0.0.1', port);
    await receiver.connectPeer(providerKey, '127.0.0.1', port);
    const replay = await replayAuthorization(receiver, providerKey, captured.payload, decodeJitAck);
    assert.equal(replay.accepted, true, replay.reason);
    assert.deepEqual(replay.interceptScid, captured.ack.interceptScid);
    assert.equal(replay.flatFeeSat, captured.ack.flatFeeSat);
    assert.equal(replay.feePpm, captured.ack.feePpm);
    assert.equal(replay.feeMode, 'skim');
    await wait('payer channel reestablished', () => payer.listChannels().some(channel =>
      channel.peerPubkey === providerKey && channel.htlcUsable));
    pass('unchanged receiver authorizes one multipart invoice and provider restart preserves registration', { amountSats });

    const sender = payer.getNode();
    assert.equal(typeof sender.sendPaymentMpp, 'function', 'Built Beignet must provide its existing MPP sender');
    const manager = sender.getChannelManager();
    const payerChannel = payer.listChannels().find(channel => channel.peerPubkey === providerKey && channel.htlcUsable);
    const payerState = manager.getChannel(Buffer.from(payerChannel.channelId, 'hex')).getFullState();
    const sourceScid = payerState.shortChannelId ?? payerState.scidAlias;
    assert.ok(Buffer.isBuffer(sourceScid) && sourceScid.length === 8);
    const finalCltv = (invoice.minFinalCltvExpiry ?? 18) + 12;
    const routeFeeMsat = BigInt(hint.feeBaseMsat) + partMsat * BigInt(hint.feeProportionalMillionths) / 1000000n;
    const part = () => ({
      hops: [
        { pubkey: Buffer.from(providerKey, 'hex'), shortChannelId: Buffer.from(sourceScid),
          amountToForwardMsat: partMsat + routeFeeMsat, outgoingCltvValue: finalCltv + hint.cltvExpiryDelta,
          feeBaseMsat: hint.feeBaseMsat, feeProportionalMillionths: hint.feeProportionalMillionths, cltvExpiryDelta: hint.cltvExpiryDelta },
        { pubkey: Buffer.from(receiverKey, 'hex'), shortChannelId: Buffer.from(hint.shortChannelId),
          amountToForwardMsat: partMsat, outgoingCltvValue: finalCltv,
          feeBaseMsat: 0, feeProportionalMillionths: 0, cltvExpiryDelta: finalCltv },
      ], totalAmountMsat: partMsat + routeFeeMsat, totalFeeMsat: routeFeeMsat, totalCltvDelta: finalCltv + hint.cltvExpiryDelta,
    });
    const routes = { parts: [part(), part()], totalAmountMsat: (partMsat + routeFeeMsat) * 2n, totalFeeMsat: routeFeeMsat * 2n };
    const dispatched = [];
    const receivedParts = new Map();
    const addHtlc = manager.addHtlc;
    manager.addHtlc = function (channelId, amountMsat, hash, ...rest) {
      if (hash.equals(invoice.paymentHash)) {
        const htlcId = this.getChannel(channelId).getFullState().localHtlcCounter;
        dispatched.push({ channelId: channelId.toString('hex'), htlcId: htlcId.toString(), amountMsat: Number(amountMsat) });
      }
      return addHtlc.call(this, channelId, amountMsat, hash, ...rest);
    };
    const log = value => {
      if (value.category !== 'htlc' || value.action !== 'received' || value.data.paymentHash !== captured.invoice.paymentHash) return;
      const item = { channelId: value.data.channelId, htlcId: value.data.htlcId, amountMsat: Number(value.data.amountMsat) };
      receivedParts.set(item.channelId + ':' + item.htlcId, item);
    };
    receiver.getNode().on('log', log);
    restoreObserver = () => { manager.addHtlc = addHtlc; receiver.getNode().removeListener('log', log); };
    // Discard setup events before dispatch so each later forwarding event is
    // attributable to this single isolated payment. Do not log raw events.
    await primary.request('events');
    const initial = sender.sendPaymentMpp(captured.invoice.bolt11, {
      paymentHash: invoice.paymentHash, paymentSecret: invoice.paymentSecret, amountMsat: partMsat * 2n,
    }, routes, finalCltv);
    assert.notEqual(initial.status, 'FAILED', initial.failureReason);
    assert.equal(dispatched.length, 2, 'The existing MPP sender must dispatch exactly two real HTLCs');
    assert.equal(new Set(dispatched.map(item => item.channelId + ':' + item.htlcId)).size, 2);
    assert.deepEqual(dispatched.map(item => item.amountMsat), [Number(partMsat + routeFeeMsat), Number(partMsat + routeFeeMsat)]);
    pass('existing Beignet MPP sender dispatches two distinct HTLCs to the same intercept SCID', {
      interceptScid: hint.shortChannelId.toString('hex'), dispatched,
    });
    const payment = await wait('two-part payer completion', () => {
      const current = payer.getPayment(captured.invoice.paymentHash);
      return current && current.status !== 'PENDING' && current;
    });
    assert.equal(payment.status, 'COMPLETED', payment.failureDescription);
    const received = await wait('two-part receiver completion', () => {
      const current = receiver.getPayment(captured.invoice.paymentHash);
      return current?.status === 'COMPLETED' && current;
    });
    const home = await wait('two-part committed receiver balance', () => {
      const channels = receiver.listChannels().filter(channel => channel.peerPubkey === providerKey);
      return channels.length === 1 && channels[0].htlcUsable && channels[0].htlcCount === 0 &&
        channels[0].localBalanceSats === (priorHome?.localBalanceSats || 0) + amountSats - feeSats && channels[0];
    });
    const forwarded = [];
    await wait('two native forwarding outcomes', async () => {
      for (const event of await primary.request('events')) {
        if (event.startsWith('PaymentForwarded {')) forwarded.push(forwardedProof(event));
      }
      return forwarded.length >= 2;
    });
    assert.equal(forwarded.length, 2);
    assert.equal(dispatched.length, 2, 'A failed MPP attempt must not be hidden by single-part retry');
    assert.equal(receivedParts.size, 2, 'Receiver must commit two distinct forwarded HTLCs');
    assert.equal([...receivedParts.values()].reduce((sum, item) => sum + item.amountMsat, 0), (amountSats - feeSats) * 1000);
    assert.equal(forwarded.reduce((sum, item) => sum + item.forwardedMsat, 0), (amountSats - feeSats) * 1000);
    assert.equal(forwarded.reduce((sum, item) => sum + item.feeMsat, 0), feeSats * 1000 + Number(routeFeeMsat * 2n));
    assert.equal(forwarded.reduce((sum, item) => sum + item.skimMsat, 0), feeSats * 1000);
    assert.equal(home.localBalanceSats, (priorHome?.localBalanceSats || 0) + amountSats - feeSats);
    assert.equal((await primary.request('channels')).filter(channel => channel.counterpartyNodeId === receiverKey).length, 1);
    if (priorHome) {
      assert.notEqual(home.fundingTxid, priorHome.fundingTxid);
      assert.ok(home.capacitySats > priorHome.capacitySats);
      const native = (await primary.request('channels')).find(channel => channel.counterpartyNodeId === receiverKey);
      assert.equal(native.fundingTxid, home.fundingTxid);
      assert.equal(native.isUsable, true);
    }
    pass('native primary forwards both parts through one home and charges its flat fee once', {
      paymentHash: captured.invoice.paymentHash, receivedSats: amountSats - feeSats, feeSats,
      localBalanceSats: home.localBalanceSats, fundingTxid: home.fundingTxid,
      oldFundingTxid: priorHome?.fundingTxid, capacitySats: home.capacitySats,
      reportedPaymentSats: received.amountSats, forwarded, receivedParts: [...receivedParts.values()], receiverChannels: 1,
    });
    evidence.completedAt = new Date().toISOString();
    succeeded = true;
    console.log('CHICORY_MPP_INTEROP ' + JSON.stringify(evidence));
  } catch (error) {
    console.error('MPP_INTEROP_FAIL ' + error.message);
    if (payer) console.error('PAYER_CHANNELS ' + JSON.stringify(payer.listChannels()));
    if (receiver) console.error('RECEIVER_CHANNELS ' + JSON.stringify(receiver.listChannels()));
    console.error('Retained disposable regtest state at ' + temp);
    throw error;
  } finally {
    if (restoreObserver) restoreObserver();
    if (receiver) await receiver.gracefulShutdown(5000).catch(() => {});
    if (payer) await payer.gracefulShutdown(5000).catch(() => {});
    if (primary) await primary.stop();
    if (process.env.BEIGNET_EVIDENCE_FILE) fs.writeFileSync(process.env.BEIGNET_EVIDENCE_FILE,
      JSON.stringify({ ...evidence, passed: succeeded }, null, 2) + '\n', { mode: 0o600 });
    if (succeeded && process.env.CHICORY_KEEP_TEST_STATE !== '1') fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch(error => { console.error('CHICORY_MPP_ERROR ' + error.message); process.exitCode = 1; });
