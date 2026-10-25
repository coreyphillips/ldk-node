'use strict';
// Qualification-only transport isolation. Wallet and BOLT8 code stay on the host.
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { deadline } = require('./bridge.cjs');

function verifyIsolationEvidence(value) {
  if (value.endpointProcessUid !== 1000 || value.noNewPrivileges !== '1' ||
    !['capabilities', 'permittedCapabilities', 'inheritableCapabilities', 'ambientCapabilities']
      .every(field => /^0+$/.test(value[field]))) {
    throw Error('Endpoint can bypass isolation');
  }
  for (const command of ['iptables', 'ip6tables']) {
    const rules = value.firewall[command].rules.split('\n').filter(Boolean);
    if (rules.find(line => line.startsWith('-A OUTPUT ')) !==
      '-A OUTPUT -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY') throw Error('Missing endpoint UDP gate');
    const chain = rules.filter(line => line.startsWith('-A CHICORY_RELAY_ONLY '));
    const expected = command === 'iptables' ? [
      '-A CHICORY_RELAY_ONLY -d 127.0.0.11/32 -j ACCEPT', '-A CHICORY_RELAY_ONLY -j DROP',
    ] : ['-A CHICORY_RELAY_ONLY -j DROP'];
    if (JSON.stringify(chain) !== JSON.stringify(expected)) throw Error('Unexpected UDP escape rule');
  }
}

function createRelayFactory({ source, image = 'chicory-iroh-relay-local:1.1.0', onEvidence = () => {} } = {}) {
  const { IrohTransport } = require(path.join(source ?? path.resolve(__dirname, '../../../../testing/beignet'), 'dist/lightning/transport/iroh.js'));
  return async function isolatedEndpoint(options) {
    const name = 'chicory-iroh-relay-' + randomBytes(8).toString('hex');
    const network = name + '-net';
    // A user-defined network supplies Docker's local 127.0.0.11 DNS service.
    execFileSync('docker', ['network', 'create', network], { stdio: 'ignore', timeout: 15000 });
    const child = spawn('docker', ['run', '--rm', '-i', '--name', name,
      '--network', network, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
      '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--security-opt', 'no-new-privileges',
      '--pids-limit', '128', '--memory', '512m', '--cpus', '2', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', image], { stdio: ['pipe', 'pipe', 'pipe'] });
    let sequence = 0, input = '', stderr = '', closing, closed = false, inbound, inboundError;
    const pending = new Map(), streams = new Map(), earlyClosed = new Set();
    const evidence = { container: name, image, endpointProcessUid: undefined, completed: [] };
    child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-8192); });
    function rejectPending() {
      closed = true;
      for (const p of pending.values()) { clearTimeout(p.timer); p.reject(Error('Isolated endpoint stopped')); }
      pending.clear();
      for (const s of streams.values()) s.resolve();
      streams.clear();
    }
    child.on('error', rejectPending);
    child.on('exit', rejectPending);
    function rpc(op, fields = {}, timeout = 40000) {
      if (closed || pending.size >= 32) return Promise.reject(Error('Isolated endpoint unavailable or busy'));
      const id = ++sequence;
      const line = JSON.stringify({ id, op, ...fields }) + '\n';
      if (line.length > 100000) return Promise.reject(Error('Oversized endpoint request'));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(Error('Isolated endpoint operation timed out')); }, timeout);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(line, error => {
          if (error) { clearTimeout(timer); pending.delete(id); reject(Error('Endpoint input closed')); }
        });
      });
    }
    function streamHandle(result) {
      const id = result.stream;
      let diagnostics = result.diagnostics, resolve;
      const closedPromise = new Promise(done => { resolve = done; });
      streams.set(id, { resolve, update: d => { diagnostics = d; } });
      if (earlyClosed.delete(id)) resolve();
      return {
        async read(limit) {
          const r = await rpc('read', { stream: id, size: Math.min(limit, 65536) }, 180000);
          diagnostics = r.diagnostics;
          return Uint8Array.from(Buffer.from(r.bytes, 'base64'));
        },
        async writeAll(data) {
          for (let offset = 0; offset < data.length; offset += 32768) {
            diagnostics = await rpc('write', { stream: id, bytes: Buffer.from(data.subarray(offset, offset + 32768)).toString('base64') });
          }
        },
        close() { void rpc('closeStream', { stream: id }).catch(() => {}); resolve(); },
        closed: () => closedPromise,
        diagnostics: () => diagnostics,
      };
    }
    function transport(result) { return new IrohTransport(streamHandle(result)); }
    let rawInbound;
    child.stdout.on('data', bytes => {
      input += bytes.toString('utf8');
      if (input.length > 1048576) { child.kill('SIGKILL'); rejectPending(); return; }
      let end;
      while ((end = input.indexOf('\n')) >= 0) {
        const line = input.slice(0, end); input = input.slice(end + 1);
        let message;
        try { message = JSON.parse(line); } catch { child.kill('SIGKILL'); rejectPending(); return; }
        if (message.event === 'closed') {
          const s = streams.get(message.stream);
          if (s) { s.update(message.diagnostics); s.resolve(); streams.delete(message.stream); }
          else { earlyClosed.add(message.stream); if (earlyClosed.size > 32) earlyClosed.delete(earlyClosed.values().next().value); }
          evidence.completed.push(message.diagnostics); if (evidence.completed.length > 32) evidence.completed.shift();
        } else if (message.event === 'incoming') {
          if (rawInbound) rawInbound(streamHandle(message));
          else {
            const socket = transport(message);
            if (inbound) inbound(socket); else socket.destroy();
          }
        } else {
          const p = pending.get(message.id);
          if (!p) continue;
          clearTimeout(p.timer); pending.delete(message.id);
          if (message.error) p.reject(Error(message.error)); else p.resolve(message.result);
        }
      }
    });
    async function close() {
      if (closing) return closing;
      closing = (async () => {
        try {
          if (!closed) {
            evidence.final = await rpc('stats');
            captureFirewall();
            if (evidence.endpointProcessUid !== undefined) verifyIsolationEvidence(evidence);
            await rpc('close', {}, 20000);
          }
          if (child.exitCode === null && child.signalCode === null) await deadline(once(child, 'exit'), 10000);
        } finally {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
          try { execFileSync('docker', ['rm', '-f', name], { stdio: 'ignore', timeout: 15000 }); } catch {}
          try { execFileSync('docker', ['network', 'rm', network], { stdio: 'ignore', timeout: 15000 }); } catch {}
          if (child.exitCode === null && child.signalCode === null) {
            try { await deadline(once(child, 'exit'), 10000); } catch {}
          }
          const absent = (kind, filter) => {
            try {
              return execFileSync('docker', [kind, 'ls', ...(kind === 'container' ? ['--all'] : []),
                '--filter', filter, '--format', '{{.ID}}'],
              { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 }).trim() === '';
            } catch { return false; }
          };
          evidence.exited = child.exitCode !== null || child.signalCode !== null;
          evidence.containerRemoved = absent('container', 'name=^/' + name + '$');
          evidence.networkRemoved = absent('network', 'name=^' + network + '$');
          rejectPending();
          onEvidence(evidence);
          if (!evidence.exited || !evidence.containerRemoved || !evidence.networkRemoved) {
            throw Error('Relay qualification cleanup could not be verified');
          }
        }
      })();
      return closing;
    }
    function captureFirewall() {
      evidence.firewall = {};
      for (const command of ['iptables', 'ip6tables']) {
        const execute = args => execFileSync('docker', ['exec', '--user', '0', name,
          command, ...args], { encoding: 'utf8', timeout: 10000, maxBuffer: 32768 });
        evidence.firewall[command] = { rules: execute(['-S']), counters: execute(['-nvxL', 'CHICORY_RELAY_ONLY']) };
      }
      evidence.imageId = execFileSync('docker', ['inspect', '--format', '{{.Image}}', name],
        { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 }).trim();
    }
    try {
      const result = await rpc('init', { secret: Buffer.from(options.secretKey).toString('base64'),
        discovery: options.discovery !== false, relays: options.relays });
      if (result.uid !== 1000 || result.bindingVersion !== '1.1.0' ||
        !/^0+$/.test(result.capabilities) || result.noNewPrivileges !== '1') throw Error('Invalid isolated endpoint runtime');
      evidence.endpointProcessUid = result.uid;
      evidence.capabilities = result.capabilities;
      evidence.permittedCapabilities = result.permittedCapabilities;
      evidence.inheritableCapabilities = result.inheritableCapabilities;
      evidence.ambientCapabilities = result.ambientCapabilities;
      evidence.noNewPrivileges = result.noNewPrivileges;
      evidence.bindingVersion = result.bindingVersion;
      captureFirewall();
      verifyIsolationEvidence(evidence);
      evidence.initialFirewall = structuredClone(evidence.firewall);
      return {
        address: () => result.address,
        connect: async (address, timeout) => transport(await rpc('connect', { address: {
          endpointId: address.endpointId, relayUrl: address.relayUrl,
        }, timeout }, Math.min(30000, timeout || 10000) + 5000)),
        listen(onConnection, onError) {
          rawInbound = undefined; inbound = onConnection; inboundError = onError;
          void rpc('listen').catch(error => inboundError?.(error));
        },
        listenRaw(onConnection, onError) {
          inbound = undefined; rawInbound = onConnection; inboundError = onError;
          return rpc('listen');
        },
        stopListening() { rawInbound = undefined; inbound = undefined; void rpc('stopListening').catch(() => {}); },
        close,
        qualificationStats: () => rpc('stats'),
      };
    } catch (error) {
      evidence.startupError = stderr ? 'Container startup failed; inspect local stderr separately' : error.message;
      await close().catch(() => {});
      throw error;
    }
  };
}
module.exports = { createRelayFactory, verifyIsolationEvidence };
