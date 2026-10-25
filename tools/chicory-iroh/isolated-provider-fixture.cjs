'use strict';
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { once } = require('node:events');
const { identity, deadline } = require('./bridge.cjs');
const { createRelayFactory, verifyIsolationEvidence } = require('./relay-factory.cjs');

// Test-only encrypted byte bridge. Native LDK remains outside the container and
// owns BOLT8, its keys, funding and channel state. Only the Iroh endpoint is here.
async function createIsolatedProviderFixture({ directory, port, providerKey, source, evidence }) {
  assert(Number.isInteger(port) && port > 0 && port <= 65535);
  assert(/^(02|03)[0-9a-f]{64}$/.test(providerKey));
  const connections = new Set();
  const tasks = new Set();
  let closing, terminalError;
  const secret = await identity(path.join(directory, 'iroh.key'));
  const factory = createRelayFactory({ source, onEvidence: value => { evidence.irohProviderIsolation = value; } });
  let endpoint;
  try {
    try { endpoint = await factory({ secretKey: secret, discovery: false }); }
    finally { secret.fill(0); }
    let address;
    await deadline((async () => {
      while (!(address = (await endpoint.qualificationStats()).address).relayUrl) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    })(), 15000);
    await endpoint.listenRaw(stream => {
      if (closing || connections.size >= 8) { stream.close(); return; }
      const tcp = net.connect({ host: '127.0.0.1', port });
      const pair = { stream, tcp };
      connections.add(pair);
      let finished = false;
      const finish = () => { if (finished) return; finished = true;
        stream.close(); tcp.destroy(); connections.delete(pair); };
      tcp.on('error', finish); tcp.once('close', finish);
      void stream.closed().then(finish, finish);
      tcp.setTimeout(120000, finish);
      const task = (async () => {
        try {
          await deadline(once(tcp, 'connect'), 10000);
          await Promise.race([
            (async () => { while (!finished) {
              const bytes = await stream.read(32768); if (!bytes.length) return;
              await deadline(new Promise((resolve, reject) => tcp.write(bytes, error => error ? reject(error) : resolve())), 15000);
            } })(),
            (async () => { for await (const bytes of tcp) {
              for (let i = 0; i < bytes.length; i += 32768) await deadline(stream.writeAll(bytes.subarray(i, i + 32768)), 15000);
            } })(),
          ]);
        } catch {} finally { finish(); }
      })();
      tasks.add(task); void task.finally(() => tasks.delete(task));
    }, error => { terminalError = error; for (const pair of connections) { pair.stream.close(); pair.tcp.destroy(); } });
    evidence.irohEndpointId = address.endpointId;
    evidence.irohRelayUrl = address.relayUrl;
    evidence.scope = 'ios-native-chicory-forced-public-relay';
    const close = () => closing ||= (async () => {
      endpoint.stopListening();
      for (const pair of connections) { pair.stream.close(); pair.tcp.destroy(); }
      await endpoint.close();
      await deadline(Promise.allSettled([...tasks]), 15000);
      if (terminalError) throw terminalError;
      const record = evidence.irohProviderIsolation;
      verifyIsolationEvidence(record);
      const paths = [...record.completed, ...(record.final?.active || []), ...(record.final?.completed || [])];
      assert(paths.length && paths.every(item => !item.directObserved), 'Provider relay isolation was not maintained');
      assert(paths.some(item => item.relayTxBytes > 0 && item.relayRxBytes > 0), 'No provider relay traffic was recorded');
    })();
    return { bridge: { address: () => address, close },
      uri: providerKey + '@iroh:' + address.endpointId + '?relay=' + encodeURIComponent(address.relayUrl) };
  } catch (error) { if (endpoint) await endpoint.close(); throw error; }
}
module.exports = { createIsolatedProviderFixture };
