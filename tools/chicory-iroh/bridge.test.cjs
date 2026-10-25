'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { randomBytes } = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { ALPN, identity, loadBinding, options, startBridge, deadline } = require('./bridge.cjs');

async function temporary(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chicory-iroh-'));
  return directory;
}

async function client(binding) {
  const builder = binding.Endpoint.builder();
  builder.applyMinimal();
  builder.relayMode(binding.RelayMode.disabled());
  builder.bindAddr('127.0.0.1:0');
  return builder.bind();
}

async function connect(binding, endpoint, bridge, alpn = ALPN) {
  const address = bridge.address();
  assert(address.directAddresses.length > 0);
  const destination = new binding.EndpointAddr(
    binding.EndpointId.fromBytes(Array.from(Buffer.from(address.endpointId, 'hex'))),
    undefined, address.directAddresses,
  );
  return deadline(endpoint.connect(destination, Array.from(alpn)), 5000);
}

async function eventually(predicate) {
  const until = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > until) throw new Error('Condition did not become true');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

async function echoFixture(t, extra = {}) {
  const directory = await temporary(t);
  const binding = loadBinding();
  const server = net.createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const bridge = await startBridge({
    binding, port: server.address().port, identityPath: path.join(directory, 'identity.key'),
    bindAddress: '127.0.0.1:0', ...extra,
  });
  const endpoint = await client(binding);
  t.after(async () => {
    await bridge.close(); await endpoint.close(); await new Promise(resolve => server.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { binding, bridge, endpoint };
}

test('identity persists exactly 32 bytes and refuses unsafe files', async t => {
  const directory = await temporary(t);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'identity.key');
  const first = await identity(file);
  const second = await identity(file);
  assert.deepEqual(first, second);
  assert.equal(first.length, 32);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  first.fill(0); second.fill(0);
  await fs.chmod(file, 0o644);
  await assert.rejects(identity(file), /mode 0600/);
  await fs.chmod(file, 0o600);
  const link = path.join(directory, 'link');
  await fs.symlink(file, link);
  await assert.rejects(identity(link), /regular 32-byte/);
  await fs.truncate(file, 31);
  await assert.rejects(identity(file), /regular 32-byte/);
});

test('native destination is explicit loopback with bounded configuration', () => {
  const valid = { port: 9735, identityPath: '/tmp/example-iroh-identity' };
  for (const host of ['localhost', '127.0.0.2', '0.0.0.0', 'example.com', '::']) {
    assert.throws(() => options({ ...valid, host }), /loopback/);
  }
  for (const port of [0, 65536, 1.5, NaN]) assert.throws(() => options({ ...valid, port }));
  assert.throws(() => options({ ...valid, relays: ['https://user:password@example.com'] }));
  assert.throws(() => options({ ...valid, maxConnections: 129 }));
  assert.throws(() => options({ ...valid, maxPending: 33 }));
  assert.equal(options({ ...valid, host: '::1' }).discovery, false);
  assert.deepEqual(options(valid).relays, []);
});

test('explicit relay startup times out and closes without announcing readiness', async t => {
  const directory = await temporary(t);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let closed = 0;
  const endpoint = { online: () => new Promise(() => {}), close: async () => { closed++; } };
  const builder = {
    applyMinimal() {}, relayMode() {}, bindAddr() {}, secretKey() {}, alpns() {},
    bind: async () => endpoint,
  };
  const binding = { Endpoint: { builder: () => builder }, RelayMode: { defaultMode: () => ({}) } };
  await assert.rejects(startBridge({
    binding, port: 9735, identityPath: path.join(directory, 'identity.key'),
    defaultRelays: true, handshakeMs: 5,
  }), /Configured relay was not ready/);
  assert.equal(closed, 1);
});

function fakeBinding(endpoint) {
  const builder = {
    applyMinimal() {}, relayMode() {}, bindAddr() {}, secretKey() {}, alpns() {},
    bind: async () => endpoint,
  };
  return { Endpoint: { builder: () => builder }, RelayMode: { disabled: () => ({}) } };
}

test('terminal accept failure or unexpected exhaustion closes the endpoint once', async t => {
  const directory = await temporary(t);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  for (const failure of [true, false]) {
    let closeCalls = 0;
    const endpoint = {
      acceptNext: async () => { if (failure) throw Error('Injected failure'); },
      setAlpns() {}, close: async () => { closeCalls++; },
    };
    const bridge = await startBridge({
      binding: fakeBinding(endpoint), port: 9735,
      identityPath: path.join(directory, String(failure) + '.key'),
    });
    assert.deepEqual(await deadline(bridge.waitForShutdown(), 1000), { failed: true });
    assert.equal(bridge.statistics().failed, true);
    assert.equal(closeCalls, 1);
    await bridge.close();
    assert.equal(closeCalls, 1);
  }
});

test('terminal refusal failure closes the endpoint and releases a pending handshake', async t => {
  const directory = await temporary(t);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let accepted = 0, refused = 0, closeCalls = 0, connectionCloses = 0, release;
  const connection = { close() { connectionCloses++; } };
  const connecting = new Promise(resolve => { release = () => resolve(connection); });
  const endpoint = {
    async acceptNext() {
      if (++accepted === 1) return { accept: async () => ({ connect: () => connecting }) };
      return { refuse: async () => { refused++; throw Error('Injected refusal failure'); } };
    },
    setAlpns() {}, close: async () => { closeCalls++; release(); },
  };
  const bridge = await startBridge({
    binding: fakeBinding(endpoint), port: 9735, maxPending: 1,
    identityPath: path.join(directory, 'identity.key'),
  });
  assert.deepEqual(await deadline(bridge.waitForShutdown(), 1000), { failed: true });
  assert.equal(refused, 1);
  assert.equal(closeCalls, 1);
  assert.equal(connectionCloses, 1);
  assert.deepEqual(bridge.statistics(), { pending: 0, active: 0, failed: true });
});

test('CLI observes terminal accept failure, closes the endpoint and exits nonzero', async t => {
  const directory = await temporary(t);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path.join(directory, 'package.json'), JSON.stringify({ name: '@number0/iroh', version: '1.1.0' }));
  await fs.writeFile(path.join(directory, 'index.js'), `
    const fs = require('node:fs'), path = require('node:path');
    const endpoint = {
      acceptNext: () => new Promise((_, reject) => setTimeout(() => reject(Error('Injected failure')), 20)),
      close: async () => fs.writeFileSync(path.join(__dirname, 'closed'), 'yes'),
      setAlpns() {}, id: () => ({ toBytes: () => Array(32).fill(1) }),
      addr: () => ({ relayUrl: () => undefined, directAddresses: () => [] }),
    };
    const builder = { applyMinimal() {}, relayMode() {}, bindAddr() {}, secretKey() {}, alpns() {}, bind: async () => endpoint };
    module.exports = { Endpoint: { builder: () => builder }, RelayMode: { disabled: () => ({}) } };
  `);
  const child = spawn(process.execPath, [path.join(__dirname, 'bridge.cjs'),
    '--identity', path.join(directory, 'identity.key'), '--port', '9735',
    '--node-id', '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'], {
    env: { ...process.env, IROH_BINDING_PATH: directory }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; });
  child.stderr.on('data', bytes => { stderr += bytes; });
  const [code, signal] = await deadline(once(child, 'close'), 5000);
  assert.equal(code, 1);
  assert.equal(signal, null);
  assert.equal(JSON.parse(stdout.trim()).ready, true);
  assert.match(stderr, /transport or shutdown failure/);
  assert.equal(await fs.readFile(path.join(directory, 'closed'), 'utf8'), 'yes');
});

test('native addon direct path preserves ordered bytes with bounded writes', { timeout: 20000 }, async t => {
  const { binding, bridge, endpoint } = await echoFixture(t);
  const connection = await connect(binding, endpoint, bridge);
  t.after(() => connection.close(0n, []));
  const stream = await connection.openBi();
  const bytes = randomBytes(512 * 1024 + 7);
  const received = [];
  await deadline(Promise.all([
    (async () => {
      for (let offset = 0; offset < bytes.length; offset += 8192) {
        await stream.send.writeAll(Array.from(bytes.subarray(offset, offset + 8192)));
      }
    })(),
    (async () => {
      let remaining = bytes.length;
      while (remaining) {
        const chunk = Buffer.from(await stream.recv.read(Math.min(remaining, 16384)));
        assert(chunk.length > 0 && chunk.length <= 16384);
        received.push(chunk); remaining -= chunk.length;
      }
    })(),
  ]), 10000);
  assert.deepEqual(Buffer.concat(received), bytes);
  assert(connection.paths().some(item => item.isSelected && item.isIp));
  assert.equal(bridge.statistics().active, 1);
  assert.equal(bridge.statistics().pending, 0);
  connection.close(0n, []);
  await eventually(() => bridge.statistics().active === 0);
});

test('connection admission and pending stream deadline remain bounded', { timeout: 20000 }, async t => {
  const { binding, bridge, endpoint } = await echoFixture(t, { maxConnections: 1, maxPending: 1, handshakeMs: 600 });
  const connection = await connect(binding, endpoint, bridge);
  await eventually(() => bridge.statistics().pending === 1);
  await assert.rejects(connect(binding, endpoint, bridge));
  await deadline(connection.closed(), 3000);
  await eventually(() => bridge.statistics().pending === 0);
  const retry = await connect(binding, endpoint, bridge);
  retry.close(0n, []);
});

test('wrong ALPN and unexpected datagrams cannot create a second transport', { timeout: 20000 }, async t => {
  const { binding, bridge, endpoint } = await echoFixture(t);
  await assert.rejects(connect(binding, endpoint, bridge, Buffer.from('other/protocol')));
  const connection = await connect(binding, endpoint, bridge);
  const stream = await connection.openBi();
  await stream.send.writeAll([1]);
  assert.deepEqual(await stream.recv.readExact(1), [1]);
  connection.sendDatagram([1]);
  await deadline(connection.closed(), 3000);
  await eventually(() => bridge.statistics().active === 0);
});

test('shutdown cancels a stream waiting for its first bytes', { timeout: 20000 }, async t => {
  const { binding, bridge, endpoint } = await echoFixture(t);
  const connection = await connect(binding, endpoint, bridge);
  await bridge.close();
  await deadline(connection.closed(), 3000);
  assert.deepEqual(bridge.statistics(), { pending: 0, active: 0, failed: false });
  assert.deepEqual(await bridge.waitForShutdown(), { failed: false });
});

// Optional read-only native interoperability. The Rust example uses a disposable
// wallet and never mines, funds, opens channels, or changes the shared regtest.
test('BOLT8 authenticates native LDK and decrypts its init over Iroh', {
  skip: !process.env.LDK_TEST_BINARY || !process.env.LDK_TEST_CHAIN_SOURCE,
  timeout: 60000,
}, async t => {
  const directory = await temporary(t);
  const binding = loadBinding();
  const reservation = net.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const native = spawn(process.env.LDK_TEST_BINARY, [path.join(directory, 'ldk'), String(port), process.env.LDK_TEST_CHAIN_SOURCE], { stdio: ['pipe', 'pipe', 'pipe'] });
  native.stderr.resume();
  let bridge;
  let endpoint;
  t.after(async () => {
    if (bridge) await bridge.close();
    if (endpoint) await endpoint.close();
    if (native.pid && native.exitCode === null) {
      native.stdin.write(JSON.stringify({ id: 1, method: 'stop' }) + '\n');
      try { await deadline(once(native, 'exit'), 15000); }
      catch { native.kill('SIGKILL'); await deadline(once(native, 'exit'), 5000); }
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  const ready = await deadline(new Promise((resolve, reject) => {
    let data = '';
    native.stdout.setEncoding('utf8');
    native.stdout.on('data', chunk => {
      data += chunk;
      if (data.length > 65536) return reject(new Error('Oversized native ready response'));
      const end = data.indexOf('\n');
      if (end >= 0) {
        try { const value = JSON.parse(data.slice(0, end)); if (value.ready) resolve(value); }
        catch { reject(new Error('Invalid native ready response')); }
      }
    });
    native.once('error', reject);
    native.once('exit', () => reject(new Error('Native example exited before ready')));
  }), 30000);
  bridge = await startBridge({ binding, port, identityPath: path.join(directory, 'identity.key'), bindAddress: '127.0.0.1:0' });
  endpoint = await client(binding);
  const connection = await connect(binding, endpoint, bridge);
  const stream = await connection.openBi();
  const source = process.env.BEIGNET_SOURCE_DIR ?? path.resolve(__dirname, '../../../../testing/beignet');
  // Only the pure BOLT8 codec is imported. No wallet or node is created.
  const { createInitiatorHandshake } = require(path.join(source, 'dist/lightning/transport/noise.js'));
  const local = randomBytes(32);
  const handshake = createInitiatorHandshake(local, Buffer.from(ready.nodeId, 'hex'));
  await stream.send.writeAll(Array.from(handshake.act1));
  handshake.processAct2(Buffer.from(await deadline(stream.recv.readExact(50), 10000)));
  await stream.send.writeAll(Array.from(handshake.createAct3()));
  const cipher = handshake.deriveTransport();
  local.fill(0);
  const receive = async () => {
    const length = cipher.decryptLength(Buffer.from(await deadline(stream.recv.readExact(18), 10000)));
    assert(length >= 2 && length <= 65535);
    return cipher.decryptBody(Buffer.from(await deadline(stream.recv.readExact(length + 16), 10000)));
  };
  // Read the authenticated native init without claiming wallet capabilities in
  // this transport-only client. The installed-phone fixture owns negotiation.
  assert.equal((await receive()).readUInt16BE(0), 16);
  connection.close(0n, []);
});
