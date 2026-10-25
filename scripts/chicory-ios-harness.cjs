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
  const deviceId = process.env.CHICORY_IOS_DEVICE_ID;
  const bundleId = process.env.CHICORY_IOS_BUNDLE_ID || 'com.chicory.primaryqualification';
  assert.match(bundleId, /^com\.chicory\.primaryqualification(?:\.[a-z0-9]+)?$/);
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
        json(response, { network: 'regtest', settings });
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
    }, 180000);
    pending.set(id, { resolve, reject, timer });
    const item = { id, operation, ...fields };
    if (poll) { const response = poll; poll = undefined; json(response, item); }
    else queue.push(item);
  });
  class DeviceClient {
    constructor({ runtime, walletId }) { this.runtime = runtime; this.walletId = walletId; }
    async createWallet(options) {
      assert.equal(options.network, 'regtest');
      assert.match(options.primaryUri, /^[0-9a-f]{66}@127\.0\.0\.1:\d+$/);
      settings = {network: 'regtest', primaryUri: options.primaryUri,
        electrum: options.electrum, transport: 'native', relayUrl: '', relayToken: ''};
      const wallet = await command('createWallet', { options });
      this.walletId = wallet.id;
      return wallet;
    }
    startWallet() { return command('startWallet', { walletId: this.walletId }); }
    close() { return this.runtime.close(); }
  }
  for (const operation of ['snapshot', 'refreshWallet', 'quoteReceive', 'receive', 'prepareSend', 'send']) {
    DeviceClient.prototype[operation] = function (...args) { return command(operation, { args }); };
  }
  return {
    EmbeddedWalletClient: DeviceClient,
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

module.exports = { createIosHarness };
