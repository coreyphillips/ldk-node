'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { once } = require('node:events');
const { startTor } = require('./tor-fixture.cjs');
const { deadline } = require('./bridge.cjs');
const { createTorSocketFactory } = require('./tor-socket.cjs');

test('public Tor hidden service transports ordered bytes through the same-node fallback route', {
  skip: process.env.CHICORY_TEST_TOR_FALLBACK !== '1', timeout: 330000,
}, async t => {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {}); socket.pipe(socket);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); return new Promise(resolve => server.close(resolve)); });
  const evidence = {};
  const tor = await startTor({ port: server.address().port, evidence });
  t.after(() => tor.close());
  t.diagnostic('Tor bootstrapped; waiting for hidden-service descriptor');
  const source = process.env.BEIGNET_SOURCE_DIR ?? path.resolve(__dirname, '../../../../testing/beignet');
  const { socks5SocketFactory } = require(path.join(source, 'dist/lightning/transport/peer-manager.js'));
  const [host, rawPort] = tor.proxy.split(':');
  const connect = socks5SocketFactory({ host, port: Number(rawPort) }, 10000);
  const factory = createTorSocketFactory({ host: tor.host, port: tor.port, connect });
  let socket, lastError;
  const until = Date.now() + 120000;
  while (Date.now() < until) {
    let candidate;
    try {
      candidate = factory({ host: tor.host, port: tor.port, tls: false });
      await deadline(once(candidate, 'connect'), 15000);
      socket = candidate; break;
    } catch (error) { candidate?.destroy(); lastError = error; await new Promise(resolve => setTimeout(resolve, 1000)); }
  }
  assert(socket, 'Hidden service unreachable: ' + lastError?.message);
  socket.on('error', () => {}); t.after(() => socket.destroy());
  const payload = Buffer.from('native-primary-same-key-onion-route');
  const result = deadline(new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    socket.on('data', bytes => {
      received = Buffer.concat([received, bytes]);
      if (received.length > 1024) reject(Error('Oversized echo response'));
      if (received.length >= payload.length) resolve(received);
    });
    socket.once('error', reject); socket.once('close', () => reject(Error('Unexpected EOF')));
  }), 15000);
  socket.write(payload);
  assert.deepEqual(await result, payload);
  socket.destroy(); await tor.close();
  assert(evidence.bootstrapped && evidence.containerRemoved && evidence.networkRemoved);
});
