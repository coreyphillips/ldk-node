'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { PassThrough } = require('node:stream');
const { createTorSocketFactory } = require('./tor-socket.cjs');
const onion = 'a'.repeat(56) + '.onion';
const target = { host: onion, port: 9735, tls: false };

test('portable onion routing accepts only its exact destination and preserves duplex bytes', async t => {
  const peers = new Set();
  const server = net.createServer(socket => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); socket.pipe(socket);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { for (const p of peers) p.destroy(); return new Promise(resolve => server.close(resolve)); });
  const factory = createTorSocketFactory({ host: onion, port: 9735, connect: async (host, port) => {
    assert.equal(host, onion); assert.equal(port, 9735);
    const socket = net.connect(server.address().port, '127.0.0.1'); await once(socket, 'connect'); return socket;
  } });
  assert.throws(() => factory({ ...target, host: 'b'.repeat(56) + '.onion' }));
  assert.throws(() => factory({ ...target, port: 9736 }));
  assert.throws(() => factory({ ...target, tls: true }));
  const socket = factory(target); t.after(() => socket.destroy());
  await once(socket, 'connect');
  const bytes = Buffer.alloc(131072, 19), received = [];
  let length = 0;
  const done = new Promise(resolve => socket.on('data', value => {
    received.push(value); length += value.length; if (length >= bytes.length) resolve();
  }));
  socket.write(bytes); await done;
  assert.deepEqual(Buffer.concat(received), bytes);
});

test('cancelled Tor dials retain the bounded slot until their late sockets are closed', async () => {
  const pending = [], sockets = [];
  const factory = createTorSocketFactory({ host: onion, port: 9735,
    connect: () => new Promise(resolve => pending.push(resolve)) });
  for (let i = 0; i < 8; i++) sockets.push(factory(target));
  await new Promise(resolve => setImmediate(resolve));
  const closed = sockets.map(socket => once(socket, 'close'));
  for (const socket of sockets) socket.destroy();
  assert.throws(() => factory(target), /connection limit/);
  const late = pending.map(resolve => { const socket = new PassThrough(); resolve(socket); return socket; });
  await Promise.all(closed);
  assert(late.every(socket => socket.destroyed));
});

test('Tor host adapter refuses excess buffered writes before a connection resolves', async () => {
  let resolve;
  const factory = createTorSocketFactory({ host: onion, port: 9735,
    connect: () => new Promise(done => { resolve = done; }) });
  const socket = factory(target);
  const error = once(socket, 'error');
  await new Promise(done => setImmediate(done));
  const callback = new Promise(done => {
    assert.equal(socket.write(Buffer.alloc(262145), value => done(value)), false);
  });
  const late = new PassThrough(); resolve(late);
  assert.match((await error)[0].message, /buffer exceeded/);
  assert.match((await callback).message, /buffer exceeded/);
  assert(late.destroyed);
});
