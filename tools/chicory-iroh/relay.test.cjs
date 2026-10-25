'use strict';
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { randomBytes, createHash } = require('node:crypto');
const { startBridge, deadline } = require('./bridge.cjs');
const { createRelayFactory, verifyIsolationEvidence } = require('./relay-factory.cjs');
const enabled = process.env.CHICORY_TEST_PUBLIC_RELAY === '1';
const evidence = [];
const source = process.env.BEIGNET_SOURCE_DIR ?? path.resolve(__dirname, '../../../../testing/beignet');

test('installed wallet accepts canonical Iroh URI and only a same-key onion fallback', async () => {
  const { pathToFileURL } = require('node:url');
  const chicory = process.env.CHICORY_SOURCE_DIR ?? path.resolve(__dirname, '../../../../testing/chicory');
  const { parsePrimaryUri, parsePrimaryFallback } = await import(pathToFileURL(
    path.join(chicory, 'node_modules/@beignet/wallet-core/src/primary-uri.js')).href);
  const pubkey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const endpoint = 'ab'.repeat(32), relay = 'https://use1-1.relay.n0.iroh.link./';
  const uri = pubkey + '@iroh:' + endpoint + '?relay=' + encodeURIComponent(relay);
  const primary = parsePrimaryUri(uri);
  assert.equal(primary.uri, uri);
  assert.equal(parsePrimaryUri(pubkey + '@iroh:' + endpoint).transport.relayUrl, undefined);
  const onion = 'a'.repeat(56) + '.onion:9735';
  assert.equal(parsePrimaryFallback(primary, pubkey + '@' + onion).pubkey, pubkey);
  assert.throws(() => parsePrimaryFallback(primary, '03' + pubkey.slice(2) + '@' + onion));
  assert.throws(() => parsePrimaryFallback(primary, pubkey + '@127.0.0.1:9735'));
  assert.throws(() => parsePrimaryFallback(primary, uri));
  for (const suffix of ['&relay=' + encodeURIComponent(relay), '&direct=127.0.0.1:9999']) {
    assert.throws(() => parsePrimaryUri(uri + suffix));
  }
});

function isolation() {
  const hook = '-A OUTPUT -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY\n';
  const drop = '-A CHICORY_RELAY_ONLY -j DROP\n';
  return { endpointProcessUid: 1000, capabilities: '0000000000000000', noNewPrivileges: '1',
    permittedCapabilities: '0000000000000000', inheritableCapabilities: '0000000000000000', ambientCapabilities: '0000000000000000',
    firewall: {
      iptables: { rules: hook + '-A CHICORY_RELAY_ONLY -d 127.0.0.11/32 -j ACCEPT\n' + drop },
      ip6tables: { rules: hook + drop },
    } };
}
test('relay isolation evidence requires unprivileged endpoint and exact IPv4 and IPv6 gates', () => {
  verifyIsolationEvidence(isolation());
  for (const change of [
    value => { value.endpointProcessUid = 0; },
    value => { value.capabilities = '0000000000001000'; },
    value => { value.permittedCapabilities = '0000000000001000'; },
    value => { value.ambientCapabilities = '0000000000000080'; },
    value => { value.inheritableCapabilities = '0000000000000040'; },
    value => { value.noNewPrivileges = '0'; },
    value => { value.firewall.iptables.rules = value.firewall.iptables.rules.replace('1000', '1001'); },
    value => { value.firewall.ip6tables.rules = ''; },
    value => { value.firewall.iptables.rules = '-A OUTPUT -j ACCEPT\n' + value.firewall.iptables.rules; },
    value => { value.firewall.iptables.rules = value.firewall.iptables.rules.replace('127.0.0.11/32', '127.0.0.0/8'); },
    value => { value.firewall.ip6tables.rules += '-A CHICORY_RELAY_ONLY -j ACCEPT\n'; },
  ]) {
    const value = isolation(); change(value);
    assert.throws(() => verifyIsolationEvidence(value));
  }
});

after(async () => {
  if (enabled && process.env.CHICORY_RELAY_EVIDENCE_FILE) {
    await fs.writeFile(process.env.CHICORY_RELAY_EVIDENCE_FILE, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  }
});
function reader(socket) {
  let buffer = Buffer.alloc(0), waiting, ended = false;
  socket.on('data', bytes => {
    buffer = Buffer.concat([buffer, bytes]);
    if (buffer.length > 1048576) { socket.destroy(); ended = true; }
    waiting?.();
  });
  socket.on('error', () => { ended = true; waiting?.(); });
  socket.on('close', () => { ended = true; waiting?.(); });
  return async size => {
    while (buffer.length < size) {
      if (ended) throw Error('Transport closed before required bytes');
      await deadline(new Promise(resolve => { waiting = resolve; }), 20000);
      waiting = undefined;
    }
    const value = buffer.subarray(0, size); buffer = buffer.subarray(size); return value;
  };
}
async function isolated(t, port, discovery) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chicory-forced-relay-'));
  let bridge, endpoint;
  const result = { discovery, startedAt: new Date().toISOString() };
  evidence.push(result);
  t.after(async () => {
    if (endpoint) await endpoint.close();
    if (bridge) await bridge.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  bridge = await startBridge({ port, identityPath: path.join(directory, 'identity'),
    discovery, defaultRelays: true });
  result.relayUrl = bridge.address().relayUrl;
  endpoint = await createRelayFactory({ source, onEvidence: value => { result.isolation = value; } })({
    secretKey: randomBytes(32), discovery,
  });
  const address = bridge.address();
  const socket = await endpoint.connect({ endpointId: address.endpointId,
    ...(discovery ? {} : { relayUrl: address.relayUrl }) }, 30000);
  socket.on('error', () => {});
  t.after(() => socket.destroy());
  return { socket, endpoint, result };
}
async function prove(endpoint, result) {
  const stats = await endpoint.qualificationStats();
  const records = [...stats.active, ...stats.completed];
  assert(records.length > 0);
  assert(records.every(r => !r.directObserved));
  assert(records.some(r => r.relayTxBytes > 0 && r.relayRxBytes > 0));
  result.traffic = records;
  await endpoint.close();
  assert.equal(result.isolation.endpointProcessUid, 1000);
  assert.match(result.isolation.firewall.iptables.rules, /-A OUTPUT -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY/);
  assert.match(result.isolation.firewall.ip6tables.rules, /-A OUTPUT -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY/);
  assert.match(result.isolation.firewall.iptables.rules, /-A CHICORY_RELAY_ONLY -j DROP/);
  assert.match(result.isolation.firewall.ip6tables.rules, /-A CHICORY_RELAY_ONLY -j DROP/);
  assert.match(result.isolation.capabilities, /^0+$/);
  result.passed = true;
  result.completedAt = new Date().toISOString();
}
for (const discovery of [false, true]) {
  test('forced public relay preserves ordered bytes with ' + (discovery ? 'default discovery and no relay hint' : 'explicit relay URI'), {
    skip: !enabled, timeout: 90000,
  }, async t => {
    const sockets = new Set();
    const server = net.createServer(socket => {
      sockets.add(socket); socket.once('close', () => sockets.delete(socket));
      socket.on('error', () => {}); socket.pipe(socket);
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    t.after(() => { for (const socket of sockets) socket.destroy(); return new Promise(resolve => server.close(resolve)); });
    const { socket, endpoint, result } = await isolated(t, server.address().port, discovery);
    const read = reader(socket);
    const bytes = randomBytes(256 * 1024 + 13);
    socket.write(bytes);
    assert.deepEqual(await read(bytes.length), bytes);
    await prove(endpoint, result);
  });
}
test('forced public relay authenticates normal-feature native LDK with BOLT8', {
  skip: !enabled || !process.env.LDK_TEST_BINARY || !process.env.LDK_TEST_CHAIN_SOURCE,
  timeout: 120000,
}, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chicory-relay-native-'));
  const reservation = net.createServer(); reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port; await new Promise(resolve => reservation.close(resolve));
  const child = spawn(process.env.LDK_TEST_BINARY, [path.join(directory, 'ldk'), String(port), process.env.LDK_TEST_CHAIN_SOURCE], { stdio: ['pipe', 'pipe', 'pipe'] });
  child.stderr.resume();
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.stdin.write(JSON.stringify({ id: 1, method: 'stop' }) + '\n');
      try { await deadline(once(child, 'exit'), 15000); } catch { child.kill('SIGKILL'); }
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  const ready = await deadline(new Promise((resolve, reject) => {
    let input = '';
    child.stdout.on('data', bytes => {
      input += bytes; if (input.length > 65536) return reject(Error('Oversized native response'));
      const end = input.indexOf('\n');
      if (end >= 0) { try { const value = JSON.parse(input.slice(0, end)); if (value.ready) resolve(value); } catch { reject(Error('Invalid native response')); } }
    });
    child.once('error', reject); child.once('exit', () => reject(Error('Native host exited before readiness')));
  }), 30000);
  const { socket, endpoint, result } = await isolated(t, port, false);
  result.nativeBinarySha256 = createHash('sha256').update(await fs.readFile(process.env.LDK_TEST_BINARY)).digest('hex');
  const read = reader(socket);
  const { createInitiatorHandshake } = require(path.join(source, 'dist/lightning/transport/noise.js'));
  const key = randomBytes(32), handshake = createInitiatorHandshake(key, Buffer.from(ready.nodeId, 'hex'));
  socket.write(handshake.act1); handshake.processAct2(await read(50)); socket.write(handshake.createAct3());
  const cipher = handshake.deriveTransport(); key.fill(0);
  const size = cipher.decryptLength(await read(18)); assert(size >= 2 && size <= 65535);
  assert.equal(cipher.decryptBody(await read(size + 16)).readUInt16BE(0), 16);
  result.nativeInitAuthenticated = true;
  await prove(endpoint, result);
});
