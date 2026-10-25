'use strict';
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Qualification only: ephemeral Tor keys stay inside tmpfs and are destroyed.
async function startTor({ port, evidence = {} }) {
  assert(Number.isSafeInteger(port) && port > 0 && port <= 65535);
  const name = 'chicory-fallback-' + randomBytes(8).toString('hex');
  const network = name + '-net';
  const image = 'chicory-iroh-tor-local:1';
  const docker = args => execFileSync('docker', args,
    { encoding: 'utf8', timeout: 15000, maxBuffer: 32768, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  let closing;
  const close = () => closing ||= (async () => {
    try { docker(['rm', '-f', name]); } catch {}
    try { docker(['network', 'rm', network]); } catch {}
    evidence.containerRemoved = docker(['container', 'ls', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']) === '';
    evidence.networkRemoved = docker(['network', 'ls', '--filter', 'name=^' + network + '$', '--format', '{{.ID}}']) === '';
    assert(evidence.containerRemoved && evidence.networkRemoved, 'Tor cleanup could not be verified');
  })();
  try {
    docker(['network', 'create', network]);
    docker(['run', '-d', '--rm', '--name', name, '--network', network,
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
      '--memory', '256m', '--cpus', '1', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000',
      '-p', '127.0.0.1::9050', image, '--RunAsDaemon', '0',
      '--DataDirectory', '/tmp/tor', '--SocksPort', '0.0.0.0:9050',
      '--HiddenServiceDir', '/tmp/service', '--HiddenServiceVersion', '3',
      '--HiddenServicePort', '9735 host.docker.internal:' + port,
      '--Log', 'notice stdout']);
    evidence.imageId = docker(['inspect', '--format', '{{.Image}}', name]);
    evidence.version = docker(['exec', name, 'tor', '--version']).split('\n')[0];
    const proxy = docker(['port', name, '9050/tcp']);
    assert(/^127\.0\.0\.1:\d+$/.test(proxy));
    const until = Date.now() + 180000;
    let ready = false;
    while (Date.now() < until) {
      const output = docker(['logs', '--tail', '80', name]);
      if (output.includes('Bootstrapped 100%')) { ready = true; break; }
      assert.equal(docker(['inspect', '--format', '{{.State.Running}}', name]), 'true', 'Tor stopped during bootstrap');
      await delay(1000);
    }
    assert(ready, 'Tor bootstrap timed out');
    const host = docker(['exec', name, 'cat', '/tmp/service/hostname']);
    assert(/^[a-z2-7]{56}\.onion$/.test(host));
    evidence.bootstrapped = true;
    evidence.onion = host;
    return { host, port: 9735, proxy, close };
  } catch (error) { await close(); throw error; }
}
module.exports = { startTor };
