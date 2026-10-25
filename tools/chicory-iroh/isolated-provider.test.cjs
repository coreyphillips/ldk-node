'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { once } = require('node:events');
const { randomBytes } = require('node:crypto');
const { deadline } = require('./bridge.cjs');
const { createIsolatedProviderFixture } = require('./isolated-provider-fixture.cjs');

test('isolated provider accepts public relay bytes and bridges only its native loopback destination', {
  skip: process.env.CHICORY_TEST_PUBLIC_RELAY !== '1', timeout: 90000,
}, async t => {
  const source = process.env.BEIGNET_SOURCE_DIR ?? path.resolve(__dirname, '../../../../testing/beignet');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chicory-provider-relay-'));
  const peers = new Set();
  const server = net.createServer(socket => {
    peers.add(socket); socket.once('close', () => peers.delete(socket));
    socket.on('error', () => {}); socket.pipe(socket);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  let bridge, endpoint, socket;
  t.after(async () => {
    socket?.destroy(); if (endpoint) await endpoint.close(); if (bridge) await bridge.close();
    for (const peer of peers) peer.destroy(); await new Promise(resolve => server.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  const evidence = {};
  ({ bridge } = await createIsolatedProviderFixture({ directory, port: server.address().port,
    providerKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', source, evidence }));
  const { createNodeIrohEndpoint } = require(path.join(source, 'dist/lightning/transport/iroh-node.js'));
  const secret = randomBytes(32);
  endpoint = await createNodeIrohEndpoint({ secretKey: secret, discovery: false }); secret.fill(0);
  socket = await endpoint.connect({ endpointId: bridge.address().endpointId, relayUrl: bridge.address().relayUrl }, 20000);
  const bytes = randomBytes(256 * 1024 + 11), received = [];
  let size = 0;
  const done = deadline(new Promise((resolve, reject) => {
    socket.on('data', value => { received.push(value); size += value.length;
      if (size > bytes.length) reject(Error('Unexpected additional bytes'));
      else if (size === bytes.length) resolve(); });
    socket.on('error', reject); socket.once('close', () => reject(Error('Early stream close')));
  }), 30000);
  for (let i = 0; i < bytes.length; i += 32768) {
    if (!socket.write(bytes.subarray(i, i + 32768))) await once(socket, 'drain');
  }
  await done; assert.deepEqual(Buffer.concat(received), bytes);
  socket.destroy(); await endpoint.close(); await bridge.close();
  assert(evidence.irohProviderIsolation.containerRemoved && evidence.irohProviderIsolation.networkRemoved);
});
