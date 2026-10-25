'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('timed-out native relay dials retain admission until the actual dial terminates', async () => {
  const dials = [];
  const never = () => new Promise(() => {});
  const endpoint = {
    addr: () => ({ relayUrl: () => null, directAddresses: () => [] }),
    id: () => ({ toBytes: () => Buffer.alloc(32, 1) }),
    acceptNext: never,
    connect: () => new Promise(resolve => { dials.push(resolve); }),
    close: async () => {},
  };
  const builder = { applyMinimal() {}, relayMode() {}, secretKey() {}, alpns() {}, bind: async () => endpoint };
  const binding = { Endpoint: { builder: () => builder }, EndpointId: { fromBytes: bytes => bytes },
    EndpointAddr: class {}, RelayMode: { defaultMode() {} } };
  const context = vm.createContext({ Buffer, setTimeout, clearTimeout,
    require(name) {
      if (name === '@number0/iroh/index.js') return binding;
      if (name === '@number0/iroh/package.json') return { version: '1.1.0' };
      if (name === 'node:fs') return { readFileSync: () => 'CapEff: 0000000000000000\nCapPrm: 0000000000000000\nCapInh: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1\n' };
      throw Error('Unexpected module');
    },
    process: { stdin: { on() {} }, stdout: { write(_line, done) { done(); } },
      on() {}, getuid: () => 1000, exit() { throw Error('Unexpected exit'); } },
  });
  const source = fs.readFileSync(path.join(__dirname, 'relay/worker.cjs'), 'utf8');
  vm.runInContext(source + '\nglobalThis.hooks = {handle, acceptLoop, pending: () => pending, count: () => connections.size};', context);
  const hooks = context.hooks;
  await hooks.handle({ op: 'init', secret: Buffer.alloc(32, 1).toString('base64'), discovery: false });
  await assert.rejects(hooks.handle({ op: 'init' }), /Already initialized/);
  const request = { op: 'connect', address: { endpointId: 'ab'.repeat(32) }, timeout: 1 };
  for (let i = 0; i < 8; i++) await assert.rejects(hooks.handle(request), /Operation timed out/);
  assert.equal(hooks.pending(), 8);
  await assert.rejects(hooks.handle(request), /Connection limit/);
  assert.equal(dials.length, 8);
  let closed = 0;
  for (const resolve of dials) resolve({ close() { closed++; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(hooks.pending(), 0);
  assert.equal(hooks.count(), 0);
  assert.equal(closed, 8);
  endpoint.acceptNext = async () => null;
  await assert.rejects(hooks.acceptLoop(), /Endpoint stopped accepting/);
});
