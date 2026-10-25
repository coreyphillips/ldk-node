#!/usr/bin/env node
'use strict';

// Independent byte bridge using the public @number0/iroh 1.1.0 API.
// The ALPN and single-stream convention match Beignet's MIT-licensed transport.
// No Lightning keys, channel state, or BeignetNode process live in this bridge.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { randomBytes } = require('node:crypto');

const ALPN = Buffer.from('beignet/bolt8/1');
const CHUNK_BYTES = 32 * 1024;
const RECEIVE_WINDOW = 128 * 1024;

function integer(value, name, maximum, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Invalid ${name}`);
  }
  return value;
}

function relayUrl(value) {
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol) || !url.hostname ||
      url.username || url.password || url.hash || value.length > 2048) {
    throw new Error('Invalid relay URL');
  }
  return url.toString();
}

function options(input) {
  if (!input || !['127.0.0.1', '::1'].includes(input.host ?? '127.0.0.1')) {
    throw new Error('The native TCP destination must be an explicit loopback address');
  }
  if (typeof input.identityPath !== 'string' || !path.isAbsolute(input.identityPath)) {
    throw new Error('An absolute endpoint identity path is required');
  }
  const relays = input.relays ?? [];
  if (!Array.isArray(relays) || relays.length > 4) throw new Error('Too many relays');
  return {
    identityPath: input.identityPath,
    host: input.host ?? '127.0.0.1',
    port: integer(input.port, 'native TCP port', 65535),
    bindAddress: input.bindAddress ?? '0.0.0.0:0',
    discovery: input.discovery === true,
    defaultRelays: input.defaultRelays === true,
    relays: relays.map(relayUrl),
    maxConnections: integer(input.maxConnections ?? 32, 'connection limit', 128),
    maxPending: integer(input.maxPending ?? 8, 'pending limit', 32),
    handshakeMs: integer(input.handshakeMs ?? 10000, 'handshake timeout', 30000),
    writeMs: integer(input.writeMs ?? 15000, 'write timeout', 60000),
    idleMs: integer(input.idleMs ?? 120000, 'idle timeout', 600000),
    binding: input.binding,
  };
}

/** Read or create an independent transport identity, never a Lightning key. */
async function identity(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  let handle;
  try {
    handle = await fs.open(file, constants.O_WRONLY | constants.O_CREAT |
      constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const bytes = randomBytes(32);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { bytes.fill(0); await handle.close(); handle = undefined; }
    // Persist the directory entry as well as its contents before announcing an id.
    const directory = await fs.open(path.dirname(file), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (handle) await handle.close();
    if (error.code !== 'EEXIST') throw new Error('Could not create endpoint identity');
  }
  try {
    handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size !== 32 || (stat.mode & 0o777) !== 0o600 ||
        (process.getuid && stat.uid !== process.getuid())) {
      throw new Error('Invalid identity file');
    }
    return await handle.readFile();
  } catch {
    throw new Error('Endpoint identity must be an owned regular 32-byte file with mode 0600');
  } finally { if (handle) await handle.close(); }
}

function loadBinding() {
  // An explicit local module directory supports testing the already-installed
  // pinned addon. It is never resolved through Beignet's node entry point.
  const explicit = process.env.IROH_BINDING_PATH;
  if (explicit && !path.isAbsolute(explicit)) throw new Error('Binding path must be absolute');
  const entry = explicit ? path.join(explicit, 'index.js') : require.resolve('@number0/iroh/index.js');
  const metadata = require(path.join(path.dirname(entry), 'package.json'));
  if (metadata.name !== '@number0/iroh' || metadata.version !== '1.1.0') {
    throw new Error('The bridge requires @number0/iroh 1.1.0');
  }
  return require(entry);
}

async function deadline(promise, ms, lateDispose) {
  let expired = false;
  let timer;
  try {
    return await Promise.race([
      Promise.resolve(promise).then(value => {
        if (expired) lateDispose?.(value);
        return value;
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => { expired = true; reject(new Error('Transport timeout')); }, ms);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

function closeConnection(connection) {
  try { connection?.close(0n, []); } catch { /* Already closed. */ }
}

function connectTcp(config, attempt) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: config.host, port: config.port, highWaterMark: CHUNK_BYTES,
    });
    attempt.socket = socket;
    socket.pause();
    socket.setNoDelay(true);
    socket.once('connect', () => resolve(socket));
    socket.once('error', () => reject(new Error('Native TCP connection failed')));
    socket.once('close', () => reject(new Error('Native TCP connection closed')));
  });
}

/** Bridge exactly one ordered stream. Each direction has one bounded write in flight. */
async function pump(connection, stream, socket, config) {
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    socket.destroy();
    closeConnection(connection);
  };
  socket.setTimeout(config.idleMs, close);
  socket.once('error', close);
  socket.once('close', close);
  void connection.closed().then(close, close);
  const toNative = (async () => {
    while (!closed) {
      const bytes = await stream.recv.read(CHUNK_BYTES);
      if (!bytes.length) return;
      if (bytes.length > CHUNK_BYTES) throw new Error('Oversized native receive');
      await deadline(new Promise((resolve, reject) => {
        socket.write(Buffer.from(bytes), error => error ? reject(error) : resolve());
      }), config.writeMs);
    }
  })();
  const toIroh = (async () => {
    for await (const bytes of socket) {
      for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
        await deadline(stream.send.writeAll(Array.from(bytes.subarray(offset, offset + CHUNK_BYTES))), config.writeMs);
      }
    }
  })();
  // EOF in either direction closes both, matching the portable Iroh transport.
  void toNative.then(close, close);
  void toIroh.then(close, close);
  await Promise.allSettled([toNative, toIroh]);
}

async function startBridge(input) {
  const config = options(input);
  const binding = config.binding ?? loadBinding();
  const builder = binding.Endpoint.builder();
  if (config.discovery) builder.applyN0(); else builder.applyMinimal();
  builder.relayMode(config.relays.length ? binding.RelayMode.customFromUrls(config.relays) :
    config.defaultRelays ? binding.RelayMode.defaultMode() : binding.RelayMode.disabled());
  builder.bindAddr(config.bindAddress);
  const secret = await identity(config.identityPath);
  const secretArray = Array.from(secret);
  try { builder.secretKey(secretArray); }
  finally { secret.fill(0); secretArray.fill(0); }
  builder.alpns([Array.from(ALPN)]);
  const endpoint = await deadline(builder.bind(), config.handshakeMs, value => { void value.close().catch(() => {}); });
  if (config.defaultRelays || config.relays.length) {
    try { await deadline(endpoint.online(), config.handshakeMs); }
    catch {
      await deadline(endpoint.close(), 15000);
      throw new Error('Configured relay was not ready before the startup deadline');
    }
  }
  const attempts = new Set();
  const sessions = new Set();
  const tasks = new Set();
  let closed = false;
  let closing;
  let acceptFailure = false;
  let finish;
  const finished = new Promise(resolve => { finish = resolve; });

  function close() {
    if (closing) return closing;
    closed = true;
    try { endpoint.setAlpns([]); } catch { /* Still close the endpoint below. */ }
    for (const attempt of [...attempts, ...sessions]) {
      attempt.expired = true;
      attempt.socket?.destroy();
      closeConnection(attempt.connection);
    }
    closing = deadline((async () => {
      await endpoint.close();
      await acceptLoop;
      await Promise.allSettled([...tasks]);
    })(), 15000);
    void closing.then(
      () => finish({ failed: acceptFailure }),
      () => finish({ failed: true }),
    );
    return closing;
  }

  async function accept(incoming) {
    const attempt = { expired: false, connection: undefined, socket: undefined };
    attempts.add(attempt);
    const timer = setTimeout(() => {
      attempt.expired = true;
      attempt.socket?.destroy();
      closeConnection(attempt.connection);
    }, config.handshakeMs);
    // Timed-out native handshakes retain their pending slot until the addon
    // actually settles. An uncancellable future cannot multiply past the cap.
    try {
      const connection = await (await incoming.accept()).connect();
      attempt.connection = connection;
      if (closed || attempt.expired || !Buffer.from(connection.alpn()).equals(ALPN)) return;
      connection.setReceiveWindow(BigInt(RECEIVE_WINDOW));
      connection.setMaxConcurrentBiStreams(1n);
      connection.setMaxConcurrentUniStreams(0n);
      const unexpected = promise => { void promise.then(() => closeConnection(connection), () => {}); };
      unexpected(connection.acceptUni());
      unexpected(connection.readDatagram());
      const stream = await connection.acceptBi();
      unexpected(connection.acceptBi());
      if (closed || attempt.expired) return;
      const socket = await connectTcp(config, attempt);
      if (closed || attempt.expired) return;
      clearTimeout(timer);
      attempts.delete(attempt);
      sessions.add(attempt);
      await pump(connection, stream, socket, config);
    } catch { /* A failed unauthenticated attempt is local to this connection. */ }
    finally {
      clearTimeout(timer);
      attempt.socket?.destroy();
      closeConnection(attempt.connection);
      attempts.delete(attempt);
      sessions.delete(attempt);
    }
  }

  const acceptLoop = (async () => {
    try {
      while (!closed) {
        const incoming = await endpoint.acceptNext();
        if (!incoming) {
          if (!closed) throw new Error('Endpoint stopped accepting');
          return;
        }
        if (closed || attempts.size >= config.maxPending ||
            attempts.size + sessions.size >= config.maxConnections) {
          await incoming.refuse();
          continue;
        }
        const task = accept(incoming);
        tasks.add(task);
        void task.finally(() => tasks.delete(task));
      }
    } catch {
      if (!closed) {
        acceptFailure = true;
        // Do not await here: shutdown joins this accept loop after closing
        // the endpoint. The terminal result is observed by the CLI/host.
        void close().catch(() => {});
      }
    }
  })();

  return {
    address() {
      const address = endpoint.addr();
      return {
        endpointId: Buffer.from(endpoint.id().toBytes()).toString('hex'),
        relayUrl: address.relayUrl(), directAddresses: address.directAddresses(),
      };
    },
    statistics() { return { pending: attempts.size, active: sessions.size, failed: acceptFailure }; },
    waitForShutdown() { return finished; },
    close,
  };
}

function parseArgs(argv) {
  const config = { relays: [] };
  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index];
    if (flag === '--discovery') { config.discovery = true; continue; }
    if (flag === '--default-relays') { config.defaultRelays = true; continue; }
    const value = argv[++index];
    if (value === undefined) throw new Error('Missing option value');
    if (flag === '--identity') config.identityPath = path.resolve(value);
    else if (flag === '--port') config.port = Number(value);
    else if (flag === '--host') config.host = value;
    else if (flag === '--bind') config.bindAddress = value;
    else if (flag === '--relay') config.relays.push(value);
    else if (flag === '--node-id') config.nodeId = value;
    else throw new Error('Unknown option');
  }
  if (!/^(02|03)[0-9a-f]{64}$/i.test(config.nodeId ?? '')) throw new Error('Native Lightning node id required');
  return config;
}

async function main() {
  const config = parseArgs(process.argv.slice(2));
  const bridge = await startBridge(config);
  const address = bridge.address();
  const uri = `${config.nodeId}@iroh:${address.endpointId}${address.relayUrl ? `?relay=${encodeURIComponent(address.relayUrl)}` : ''}`;
  process.stdout.write(JSON.stringify({ ready: true, uri, ...address }) + '\n');
  const stop = () => { void bridge.close().catch(() => {}); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  const outcome = await bridge.waitForShutdown();
  process.off('SIGINT', stop);
  process.off('SIGTERM', stop);
  if (outcome.failed) process.stderr.write('Iroh bridge stopped after a transport or shutdown failure\n');
  process.exit(outcome.failed ? 1 : 0);
}

if (require.main === module) {
  main().catch(() => { process.stderr.write('Iroh bridge startup failed; check explicit options and identity permissions\n'); process.exitCode = 1; });
}

module.exports = { ALPN, CHUNK_BYTES, RECEIVE_WINDOW, identity, loadBinding, options, startBridge, deadline };
