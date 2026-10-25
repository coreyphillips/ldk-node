'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { startBridge } = require('./bridge.cjs');
const { createRelayFactory, verifyIsolationEvidence } = require('./relay-factory.cjs');

async function createRelayFixture({ directory, port, providerKey, discovery, source, evidence }) {
  const bridge = await startBridge({ identityPath: path.join(directory, 'iroh.key'), port,
    discovery, defaultRelays: true });
  const address = bridge.address();
  assert(address.relayUrl);
  const endpoints = [];
  evidence.irohIsolation = [];
  evidence.irohDiscovery = discovery;
  evidence.irohRelayUrl = address.relayUrl;
  evidence.irohEndpointId = address.endpointId;
  evidence.scope = 'installed-chicory-portable-forced-public-relay';
  const factory = createRelayFactory({ source, onEvidence: value => { evidence.irohIsolation.push(value); } });
  const originalClose = bridge.close;
  bridge.close = async () => {
    try {
      await Promise.all(endpoints.map(ep => ep.close()));
      assert(evidence.irohIsolation.length > 0, 'No isolated endpoint evidence was recorded');
      let bidirectionalRelayTraffic = false;
      for (const record of evidence.irohIsolation) {
        verifyIsolationEvidence(record);
        const traffic = [...(record.final?.active || []), ...(record.final?.completed || [])];
        assert(traffic.every(item => !item.directObserved), 'A direct path escaped relay isolation');
        bidirectionalRelayTraffic ||= traffic.some(item => item.relayTxBytes > 0 && item.relayRxBytes > 0);
      }
      assert(bidirectionalRelayTraffic, 'No bidirectional public relay traffic was recorded');
    } finally { await originalClose(); }
  };
  return {
    bridge,
    uri: providerKey + '@iroh:' + address.endpointId +
      (discovery ? '' : '?relay=' + encodeURIComponent(address.relayUrl)),
    iroh: { discovery, factory: async options => {
      const endpoint = await factory({ ...options, discovery, relays: undefined });
      const connect = endpoint.connect;
      endpoint.connect = (target, timeout) => {
        assert.equal(target.endpointId, address.endpointId);
        assert(!target.directAddresses?.length, 'Relay qualification does not supply direct hints');
        return connect(target, timeout);
      };
      endpoints.push(endpoint);
      return endpoint;
    } },
  };
}
module.exports = { createRelayFixture };
