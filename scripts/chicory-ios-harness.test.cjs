'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { isQualificationPrimaryUri, isQualificationFallbackPair } = require('./chicory-ios-harness.cjs');
const key = '02' + '11'.repeat(32);
const endpoint = '22'.repeat(32);

test('native qualification accepts only explicit isolated transports', () => {
  assert.equal(isQualificationPrimaryUri(key + '@127.0.0.1:9735'), true);
  const relay = encodeURIComponent('https://use1-1.relay.n0.iroh.link./');
  assert.equal(isQualificationPrimaryUri(key + '@iroh:' + endpoint + '?relay=' + relay), true);
  for (const uri of [
    key + '@example.com:9735',
    key + '@127.0.0.1:0',
    key + '@127.0.0.1:65536',
    '04' + '11'.repeat(32) + '@127.0.0.1:9735',
    key + '@iroh:' + endpoint,
    key + '@iroh:' + endpoint + '?relay=' + encodeURIComponent('http://use1-1.relay.n0.iroh.link/'),
    key + '@iroh:' + endpoint + '?relay=' + encodeURIComponent('https://relay.n0.iroh.link.attacker.test/'),
    key + '@iroh:' + endpoint + '?relay=' + relay + '&other=1',
    key + '@iroh:' + endpoint + '?relay=%invalid',
    null,
  ]) assert.equal(isQualificationPrimaryUri(uri), false);
});

test('native fallback requires an explicit Iroh primary and same-key v3 onion', () => {
  const primary = key + '@iroh:' + endpoint + '?relay=' + encodeURIComponent('https://use1-1.relay.n0.iroh.link./');
  const onion = 'a'.repeat(56) + '.onion:9735';
  assert.equal(isQualificationFallbackPair(primary, key + '@' + onion), true);
  for (const fallback of [
    '03' + '22'.repeat(32) + '@' + onion,
    key + '@' + 'a'.repeat(55) + '.onion:9735',
    key + '@' + '1'.repeat(56) + '.onion:9735',
    key + '@' + onion.replace(':9735', ':80'),
    key + '@127.0.0.1:9735',
    key + '@' + onion + '/path',
    undefined,
  ]) assert.equal(isQualificationFallbackPair(primary, fallback), false);
  assert.equal(isQualificationFallbackPair(key + '@127.0.0.1:9735', key + '@' + onion), false);
});
