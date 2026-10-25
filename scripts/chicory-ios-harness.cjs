'use strict';

// Loopback-only controller for the separately signed disposable simulator app.
// Wallet methods execute in Hermes through Chicory's actual device adapters.
const assert = require('node:assert/strict');
const http = require('node:http');
const { execFileSync } = require('node:child_process');

async function createIosHarness() {
  const queue = [];
  const pending = new Map();
  let serial = 0;
  let poll;
  let settings;
  let authorizedFallback;
  const walletIds = new Set();
  const deviceId = process.env.CHICORY_IOS_DEVICE_ID;
  let bundleId = process.env.CHICORY_IOS_BUNDLE_ID || 'com.chicory.primaryqualification';
  const secondBundleId = process.env.CHICORY_IOS_SECOND_BUNDLE_ID;
  assert.match(bundleId, /^com\.chicory\.primaryqualification(?:\.[a-z0-9]+)?$/);
  if (secondBundleId) {
    assert.match(secondBundleId, /^com\.chicory\.primaryqualification\.[a-z0-9]+$/);
    assert.notEqual(secondBundleId, bundleId);
    assert.ok(deviceId, 'A second isolated app requires a simulator identifier');
  }
  if (deviceId) assert.match(deviceId, /^[0-9A-Fa-f-]{36}$/);
  const simulator = (...args) => execFileSync('xcrun', ['simctl', ...args], {
    env: { ...process.env, DEVELOPER_DIR: '/Applications/Xcode.app/Contents/Developer' },
    encoding: 'utf8', timeout: 30000,
  });
  let readyResolve;
  let readyReject;
  let ready;
  const resetReady = () => {
    ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    // A pending readiness rejection must be observed even before the runner dials.
    ready.catch(() => {});
  };
  resetReady();
  const json = (response, value) => {
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify(value));
  };
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/config') {
        json(response, { network: 'regtest', settings, walletIds: [...walletIds], authorizedFallback });
        return;
      }
      if (request.method === 'GET' && request.url === '/next') {
        if (poll) json(poll, {});
        if (queue.length) json(response, queue.shift());
        else {
          poll = response;
          response.on('close', () => { if (poll === response) poll = undefined; });
        }
        return;
      }
      if (request.method !== 'POST' || !['/ready', '/result', '/failed'].includes(request.url)) {
        response.writeHead(404).end();
        return;
      }
      let body = '';
      for await (const bytes of request) {
        body += bytes.toString();
        if (Buffer.byteLength(body) > 2 * 1024 * 1024) throw Error('Simulator response exceeds limit');
      }
      const value = JSON.parse(body);
      if (request.url === '/ready') {
        assert.equal(value.platform, 'ios');
        assert.equal(value.hermes, true);
        readyResolve(value);
      } else if (request.url === '/failed') {
        readyReject(Error('Simulator entry failed: ' + String(value.message).slice(0, 500)));
      } else {
        const entry = pending.get(value.id);
        if (entry) {
          pending.delete(value.id);
          clearTimeout(entry.timer);
          if (value.error) entry.reject(Error(String(value.error).slice(0, 500)));
          else entry.resolve(value.result);
        }
      }
      json(response, { ok: true });
    } catch {
      if (!response.headersSent) response.writeHead(400);
      response.end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(31078, '127.0.0.1', resolve);
  });
  const command = (operation, fields = {}) => new Promise((resolve, reject) => {
    if (pending.size >= 16) { reject(Error('Simulator command limit reached')); return; }
    const id = ++serial;
    const timer = setTimeout(() => {
      pending.delete(id);
      const index = queue.findIndex(item => item.id === id);
      if (index >= 0) queue.splice(index, 1);
      reject(Error('Simulator command timed out: ' + operation));
    }, authorizedFallback && ['updatePrimary', 'startWallet'].includes(operation) ? 360000 : 180000);
    pending.set(id, { resolve, reject, timer });
    const item = { id, operation, ...fields };
    if (poll) { const response = poll; poll = undefined; json(response, item); }
    else queue.push(item);
  });
  class DeviceClient {
    constructor({ runtime, walletId }) { this.runtime = runtime; this.walletId = walletId; }
    async createWallet(options) {
      assert.equal(options.network, 'regtest');
      assert.ok(isQualificationPrimaryUri(options.primaryUri), 'Expected isolated TCP or explicit public-relay Iroh URI');
      settings = {network: 'regtest', primaryUri: options.primaryUri,
        electrum: options.electrum, transport: 'native', relayUrl: '', relayToken: ''};
      if (walletIds.size) {
        // The real device adapter has one wallet per network. A genuinely new
        // DF receiver must use a second app identity, never erase the first.
        assert.ok(secondBundleId && bundleId !== secondBundleId,
          'Install a second fresh qualification app for the new receiver');
        assert.equal(pending.size, 0);
        simulator('terminate', deviceId, bundleId);
        if (poll) { json(poll, {}); poll = undefined; }
        resetReady();
        bundleId = secondBundleId;
        walletIds.clear();
        simulator('launch', deviceId, bundleId);
        let timer;
        try {
          await Promise.race([ready, new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error('Second qualification app did not start')), 60000);
          })]);
        } finally { clearTimeout(timer); }
      }
      const wallet = await command('createWallet', { options });
      assert.equal(typeof wallet.id, 'string');
      assert.ok(wallet.id.length > 0 && wallet.id.length <= 160 && !walletIds.has(wallet.id));
      walletIds.add(wallet.id);
      this.walletId = wallet.id;
      return wallet;
    }
    updatePrimary(primaryUri, fallbackUri) {
      assert.deepEqual({ primaryUri, fallbackUri }, authorizedFallback, 'Only the generated disposable fallback is authorized');
      return command('updatePrimary', { primaryUri, fallbackUri });
    }
    startWallet() { return command('startWallet', { walletId: this.walletId }); }
    close() { return this.runtime.close(); }
  }
  for (const operation of ['snapshot', 'refreshWallet', 'quoteReceive', 'receive', 'prepareSend', 'send']) {
    DeviceClient.prototype[operation] = function (...args) { return command(operation, { args }); };
  }
  return {
    EmbeddedWalletClient: DeviceClient,
    authorizePrimaryFallback(primaryUri, fallbackUri) {
      assert.equal(authorizedFallback, undefined, 'Fallback authorization is immutable');
      assert.equal(isQualificationFallbackPair(primaryUri, fallbackUri), true);
      authorizedFallback = Object.freeze({ primaryUri, fallbackUri });
    },
    async createPortableRuntime() {
      let timer;
      try {
        await Promise.race([ready, new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error('Start the separate simulator qualification app')), 600000);
        })]);
      } finally { clearTimeout(timer); }
      let closed = false;
      return {
        request: body => command('request', { body }),
        async close() {
          if (!closed) {
            await command('close');
            closed = true;
            if (deviceId) {
              simulator('terminate', deviceId, bundleId);
              // A previous process's long poll must not swallow the first
              // command sent to its replacement. Wait for a fresh /ready.
              if (poll) { json(poll, {}); poll = undefined; }
              resetReady();
              simulator('launch', deviceId, bundleId);
            }
          }
        },
      };
    },
    async close() {
      if (poll) { json(poll, {}); poll = undefined; }
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(Error('Simulator harness stopped'));
      }
      pending.clear();
      queue.length = 0;
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      if (deviceId) {
        try { simulator('terminate', deviceId, bundleId); }
        catch { /* The isolated app may already have exited. */ }
      }
    },
  };
}

function isQualificationPrimaryUri(value) {
  if (typeof value !== 'string') return false;
  const tcp = /^0[23][0-9a-f]{64}@127\.0\.0\.1:([0-9]{1,5})$/.exec(value);
  if (tcp) return Number(tcp[1]) > 0 && Number(tcp[1]) <= 65535;
  const match = /^0[23][0-9a-f]{64}@iroh:[0-9a-f]{64}\?relay=([^&]+)$/.exec(value);
  if (!match) return false;
  try {
    return /^https:\/\/[a-z0-9-]+\.relay\.n0\.iroh\.link\.?\/$/.test(decodeURIComponent(match[1]));
  } catch { return false; }
}

module.exports = { createIosHarness };

module.exports.isQualificationPrimaryUri = isQualificationPrimaryUri;

function isQualificationFallbackPair(primaryUri, fallbackUri) {
  if (!isQualificationPrimaryUri(primaryUri) || !primaryUri.includes('@iroh:')) return false;
  if (typeof fallbackUri !== 'string') return false;
  const onion = /^(0[23][0-9a-f]{64})@([a-z2-7]{56})\.onion:9735$/.exec(fallbackUri);
  return !!onion && onion[1] === primaryUri.split('@')[0];
}
module.exports.isQualificationFallbackPair = isQualificationFallbackPair;
