'use strict';
// Test-only endpoint isolation. No Lightning engine or wallet runs here.
const binding = require('@number0/iroh/index.js');
const fs = require('node:fs');
const ALPN = Array.from(Buffer.from('beignet/bolt8/1'));
const connections = new Map();
const completed = [];
let endpoint, initializing = false, sequence = 0, pending = 0, requests = 0, stopping = false;
let input = '', output = Promise.resolve(), listening = false, generation = 0;

function send(value) {
  const line = JSON.stringify(value) + '\n';
  if (line.length > 100000) throw Error('Oversized response');
  output = output.then(() => new Promise((resolve, reject) => {
    process.stdout.write(line, error => error ? reject(error) : resolve());
  }));
  return output;
}
async function deadline(promise, ms, late) {
  let timer, expired = false;
  try {
    return await Promise.race([promise.then(value => {
      if (expired) late?.(value);
      return value;
    }), new Promise((_, reject) => { timer = setTimeout(() => {
      expired = true; reject(Error('Operation timed out'));
    }, ms); })]);
  } finally { clearTimeout(timer); }
}
function closeConnection(c) { try { c.close(0n, []); } catch {} }
function address() {
  const a = endpoint.addr();
  return { endpointId: Buffer.from(endpoint.id().toBytes()).toString('hex'),
    relayUrl: a.relayUrl(), directAddresses: a.directAddresses() };
}
function observe(record) {
  for (const p of record.connection.paths()) {
    if (p.isIp && (p.isSelected || p.stats.udpTxBytes || p.stats.udpRxBytes)) record.directObserved = true;
    if (p.isRelay) {
      record.relayTxBytes = Math.max(record.relayTxBytes, p.stats.udpTxBytes);
      record.relayRxBytes = Math.max(record.relayRxBytes, p.stats.udpRxBytes);
    }
  }
  return { endpointId: record.endpointId, path: record.directObserved ? 'direct' :
    record.connection.paths().some(p => p.isSelected && p.isRelay) ? 'relay' : 'unknown',
    directObserved: record.directObserved, relayTxBytes: record.relayTxBytes, relayRxBytes: record.relayRxBytes };
}
function register(connection, stream) {
  const id = ++sequence;
  const record = { id, connection, stream, read: false, write: false, directObserved: false,
    relayTxBytes: 0, relayRxBytes: 0, endpointId: Buffer.from(connection.remoteId().toBytes()).toString('hex') };
  connections.set(id, record);
  void connection.closed().then(async () => {
    const diagnostics = observe(record);
    connections.delete(id);
    completed.push(diagnostics); if (completed.length > 32) completed.shift();
    await send({ event: 'closed', stream: id, diagnostics });
  }).catch(() => {});
  return { stream: id, diagnostics: observe(record) };
}
function limit(connection, incoming) {
  connection.setReceiveWindow(131072n);
  connection.setMaxConcurrentBiStreams(incoming ? 1n : 0n);
  connection.setMaxConcurrentUniStreams(0n);
  for (const promise of [connection.acceptUni(), connection.readDatagram(), ...(!incoming ? [connection.acceptBi()] : [])]) {
    void promise.then(() => closeConnection(connection), () => {});
  }
}
async function acceptLoop() {
  while (!stopping) {
    const incoming = await endpoint.acceptNext();
    if (!incoming) { if (!stopping) throw Error('Endpoint stopped accepting'); return; }
    if (!listening || connections.size + pending >= 8) { await incoming.refuse(); continue; }
    pending++;
    const epoch = generation;
    void (async () => {
      let connection, cancelled = false;
      const attempt = (async () => {
        try {
          connection = await incoming.accept().then(a => a.connect());
          if (cancelled || stopping || !listening || epoch !== generation) return;
          limit(connection, true);
          const stream = await connection.acceptBi();
          const accepted = connection;
          void accepted.acceptBi().then(() => closeConnection(accepted), () => {});
          if (cancelled || stopping || !listening || epoch !== generation) return;
          await send({ event: 'incoming', ...register(connection, stream) });
          connection = undefined;
        } catch {} finally { if (connection) closeConnection(connection); pending--; }
      })();
      try {
        await deadline(attempt, 10000);
      } catch { cancelled = true; if (connection) closeConnection(connection); }
    })();
  }
}
async function handle(request) {
  const { op } = request;
  if (op === 'init') {
    request.stage = 'configuration';
    if (endpoint || initializing) throw Error('Already initialized');
    initializing = true;
    const secret = Buffer.from(request.secret || '', 'base64');
    if (secret.length !== 32) throw Error('Invalid endpoint identity');
    const builder = binding.Endpoint.builder();
    if (request.discovery) builder.applyN0(); else builder.applyMinimal();
    const relays = request.relays;
    if (relays !== undefined && (!Array.isArray(relays) || relays.length > 4)) throw Error('Invalid relays');
    builder.relayMode(relays === undefined ? binding.RelayMode.defaultMode() :
      relays.length ? binding.RelayMode.customFromUrls(relays) : binding.RelayMode.disabled());
    const bytes = Array.from(secret);
    try { builder.secretKey(bytes); } finally { secret.fill(0); bytes.fill(0); request.secret = ''; }
    builder.alpns([]);
    request.stage = 'bind';
    endpoint = await deadline(builder.bind(), 15000, ep => { void ep.close(); });
    request.stage = 'metadata';
    void acceptLoop().catch(() => { if (!stopping) void shutdown(1); });
    const status = fs.readFileSync('/proc/self/status', 'utf8');
    return { address: address(), uid: process.getuid(),
      capabilities: /^CapEff:\s*(\w+)/m.exec(status)?.[1],
      permittedCapabilities: /^CapPrm:\s*(\w+)/m.exec(status)?.[1],
      inheritableCapabilities: /^CapInh:\s*(\w+)/m.exec(status)?.[1],
      ambientCapabilities: /^CapAmb:\s*(\w+)/m.exec(status)?.[1],
      noNewPrivileges: /^NoNewPrivs:\s*(\d+)/m.exec(status)?.[1],
      bindingVersion: require('@number0/iroh/package.json').version };
  }
  if (!endpoint || stopping) throw Error('Endpoint unavailable');
  if (op === 'connect') {
    if (connections.size + pending >= 8) throw Error('Connection limit');
    const a = request.address;
    if (!a || !/^[0-9a-f]{64}$/.test(a.endpointId)) throw Error('Invalid endpoint id');
    const timeout = Math.max(1, Math.min(30000, Number(request.timeout) || 10000));
    pending++; let connection, cancelled = false;
    const attempt = (async () => {
      try {
        const addr = new binding.EndpointAddr(binding.EndpointId.fromBytes(Array.from(Buffer.from(a.endpointId, 'hex'))), a.relayUrl, []);
        connection = await endpoint.connect(addr, ALPN);
        if (cancelled || stopping) throw Error('Connection cancelled');
        limit(connection, false);
        const stream = await connection.openBi();
        if (cancelled || stopping) throw Error('Connection cancelled');
        return register(connection, stream);
      } catch (error) { if (connection) closeConnection(connection); throw error; }
      finally { pending--; }
    })();
    try {
      return await deadline(attempt, timeout, result => {
        const record = connections.get(result.stream); if (record) closeConnection(record.connection);
      });
    } catch (error) { cancelled = true; if (connection) closeConnection(connection); throw error; }
  }
  if (op === 'listen') { listening = true; endpoint.setAlpns([ALPN]); return true; }
  if (op === 'stopListening') { listening = false; generation++; endpoint.setAlpns([]); return true; }
  if (op === 'stats') return { address: address(), completed, active: [...connections.values()].map(observe) };
  if (op === 'close') { stopping = true; for (const r of connections.values()) closeConnection(r.connection); await deadline(endpoint.close(), 15000); return true; }
  const r = connections.get(request.stream);
  if (!r) throw Error('Stream closed');
  if (op === 'closeStream') { closeConnection(r.connection); return true; }
  if (op === 'read') {
    if (r.read) throw Error('Concurrent read');
    const size = request.size;
    if (!Number.isInteger(size) || size < 1 || size > 65536) throw Error('Invalid read size');
    r.read = true;
    try { const bytes = await r.stream.recv.read(size); return { bytes: Buffer.from(bytes).toString('base64'), diagnostics: observe(r) }; }
    finally { r.read = false; }
  }
  if (op === 'write') {
    if (r.write || typeof request.bytes !== 'string' || request.bytes.length > 87384) throw Error('Invalid write');
    const bytes = Buffer.from(request.bytes, 'base64');
    if (bytes.length > 65536) throw Error('Oversized write');
    r.write = true;
    try { await deadline(r.stream.send.writeAll(Array.from(bytes)), 15000); return observe(r); }
    finally { r.write = false; }
  }
  throw Error('Unknown operation');
}
async function shutdown(code) {
  if (!stopping) { stopping = true; for (const r of connections.values()) closeConnection(r.connection); await deadline(endpoint?.close() || Promise.resolve(), 15000).catch(() => {}); }
  await deadline(output, 5000).catch(() => {}); process.exit(code);
}
process.stdin.on('data', bytes => {
  input += bytes.toString('utf8');
  if (input.length > 262144) return void shutdown(1);
  let end;
  while ((end = input.indexOf('\n')) >= 0) {
    const line = input.slice(0, end); input = input.slice(end + 1);
    let request;
    try { request = JSON.parse(line); if (!Number.isSafeInteger(request.id) || ++requests > 64) throw Error(); }
    catch { return void shutdown(1); }
    void handle(request).then(result => send({ id: request.id, result }), error => send({ id: request.id,
      error: 'Iroh endpoint ' + request.op + ' failed' + (request.stage ? ' at ' + request.stage : '') +
        (error.message === 'Operation timed out' ? ' (timeout)' : '') }))
      .finally(() => { requests--; if (request.op === 'close') void shutdown(0); })
      .catch(() => void shutdown(1));
  }
});
process.stdin.on('end', () => void shutdown(0));
process.on('SIGTERM', () => void shutdown(0));
