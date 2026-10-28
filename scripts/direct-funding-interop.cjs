#!/usr/bin/env node
/*
 * Real Beignet/native bgnq interoperability on a disposable Bitcoin regtest chain.
 * Uses the checked-out Beignet protocol, peer transport, channel state machine,
 * wallet signatures and a minimal Bitcoin Core chain adapter. No channel mocks.
 *
 * cargo build --features chicory --example chicory-primary
 * node scripts/direct-funding-interop.cjs --rpc-url rpc://USER:PASS@127.0.0.1:PORT --beignet /path/to/beignet
 * Beignet's node_modules must already be installed. Evidence and journals go to a
 * new temporary directory. The RPC endpoint MUST identify itself as regtest.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const net = require('node:net');
const http = require('node:http');
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const assert = require('node:assert/strict');
const args = Object.fromEntries(process.argv.slice(2).reduce((out, x, i, all) => i % 2 ? out : [...out, [x, all[i+1]]], []));
const rpcUrl = args['--rpc-url'] || process.env.BGNQ_RPC_URL;
const beignetDir = args['--beignet'] || process.env.BEIGNET_DIR;
if (!rpcUrl || !beignetDir) throw new Error('--rpc-url and --beignet are required');
const root = path.resolve(__dirname, '..');
const beignet = path.resolve(beignetDir);
process.env.TS_NODE_PROJECT = path.join(beignet, 'tsconfig.json');
require(path.join(beignet, 'node_modules/ts-node/register/transpile-only'));
const load = file => require(path.join(beignet, file));
const bitcoin = load('node_modules/bitcoinjs-lib');
const { LightningNode } = load('src/lightning/node/lightning-node.ts');
const { SqliteStorage } = load('src/lightning/storage/sqlite-storage.ts');
const { FeatureFlags, Feature } = load('src/lightning/features/flags.ts');
const { REGTEST_CHAIN_HASH, ChannelState } = load('src/lightning/channel/types.ts');
const { Network } = load('src/lightning/invoice/types.ts');
const { deriveLightningKeysFromMnemonic, LnCoinType } = load('src/lightning/keys/wallet-keys.ts');
const { DirectFundingSender } = load('src/lightning/direct-funding/sender/engine.ts');
const { DirectFundingPaymentStore } = load('src/lightning/direct-funding/sender/records.ts');
const { chainHashForNetwork } = load('src/lightning/direct-funding/types.ts');
const { FakeSenderWallet, makeCoin } = load('tests/lightning/helpers/df-sender.ts');
const run = fs.mkdtempSync(path.join(os.tmpdir(), 'bgnq-interop-'));
const endpoint = new URL(rpcUrl.replace(/^rpc:/, 'http:'));
const auth = Buffer.from(`${decodeURIComponent(endpoint.username)}:${decodeURIComponent(endpoint.password)}`).toString('base64');
const rpcWallet = `bgnq-interop-${Date.now()}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const evidence = [];
const nativeNodes = [];
const beignetNodes = [];
function log(name, data = {}) { const item = { name, ...data }; evidence.push(item); process.stdout.write(JSON.stringify(item) + '\n'); }
async function rpc(method, params = [], wallet = false) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: endpoint.hostname, port: endpoint.port, path: wallet ? `/wallet/${rpcWallet}` : '/', method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body) } }, response => {
      let bytes = ''; response.on('data', chunk => bytes += chunk); response.on('end', () => {
        try { const value = JSON.parse(bytes); if (value.error) reject(new Error(JSON.stringify(value.error))); else resolve(value.result); } catch (e) { reject(e); }
      });
    });
    req.setTimeout(30000, () => req.destroy(new Error(`RPC ${method} timed out`)));
    req.on('error', reject); req.end(body);
  });
}
async function wait(label, probe, milliseconds = 90000) {
  const until = Date.now() + milliseconds;
  while (Date.now() < until) { const result = await probe(); if (result) return result; await sleep(250); }
  throw new Error(`Timed out: ${label}`);
}
async function freePort() {
  return new Promise((resolve, reject) => { const server = net.createServer(); server.once('error', reject); server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); }); });
}
class Native {
  static async start(name, primary) {
    const self = new Native(); self.name = name; self.seq = 0; self.pending = new Map();
    self.port = await freePort(); self.dir = path.join(run, name); fs.mkdirSync(self.dir);
    const ready = new Promise((resolve, reject) => { self.readyResolve = resolve; self.readyReject = reject; });
    const env = { ...process.env }; delete env.LFBW_PRIMARY_URI; if (primary) env.LFBW_PRIMARY_URI = primary;
    self.proc = spawn(path.join(root, 'target/debug/examples/chicory-primary'), [self.dir, String(self.port), rpcUrl], { env, stdio:['pipe','pipe',fs.openSync(path.join(run, `${name}.stderr`), 'a')] });
    nativeNodes.push(self);
    readline.createInterface({ input:self.proc.stdout }).on('line', line => {
      let msg; try { msg = JSON.parse(line); } catch { return; }
      if (msg.ready) { self.readyResolve(msg); return; }
      const pending = self.pending.get(msg.id); if (!pending) return;
      clearTimeout(pending.timer); self.pending.delete(msg.id);
      if (msg.error) pending.reject(new Error(`${name}: ${msg.error}`)); else pending.resolve(msg.result);
    });
    self.proc.on('error', error => self.readyReject(error));
    self.proc.on('exit', code => { self.readyReject(new Error(`${name} exited ${code}`)); for (const {reject,timer} of self.pending.values()) { clearTimeout(timer); reject(new Error(`${name} exited ${code}`)); } self.pending.clear(); });
    const startupTimer = setTimeout(() => self.readyReject(new Error(`${name} startup timed out`)),90000);
    try { self.ready = await ready; } finally { clearTimeout(startupTimer); }
    return self;
  }
  call(method, params = {}) { const id = ++this.seq; return new Promise((resolve, reject) => { const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`${this.name} ${method} timed out`)); }, 180000); this.pending.set(id, {resolve,reject,timer}); this.proc.stdin.write(JSON.stringify({id,method,...params})+'\n'); }); }
  async stop() { if (this.proc.exitCode !== null) return; try { await this.call('stop'); } catch {} if (this.proc.exitCode === null) this.proc.kill(); }
}
const hashScript = script => crypto.createHash('sha256').update(script).digest().reverse().toString('hex');
/* An actual chain index scoped to blocks created by this test, plus the mempool. */
class CoreChain {
  constructor(height) { this.height = height; this.transactions = new Map(); this.headers = []; this.scripts = new Map(); }
  async getTransaction(txid) { const raw = Buffer.from(await rpc('getrawtransaction',[txid]),'hex'); const tx = bitcoin.Transaction.fromBuffer(raw); assert.equal(tx.getId(),txid); if (!this.transactions.has(txid)) this.transactions.set(txid,{tx,height:0}); return raw; }
  async broadcastTransaction(raw) { const txid = await rpc('sendrawtransaction',[raw]); await this.refresh(); return txid; }
  async subscribeToHeaders(callback) { this.headers.push(callback); callback(this.height); }
  async subscribeToScriptHash(hash, callback) { if (!this.scripts.has(hash)) this.scripts.set(hash,[]); this.scripts.get(hash).push(callback); queueMicrotask(callback); }
  async getScriptHashHistory(hash) {
    return [...this.transactions].filter(([, {tx}]) => tx.outs.some(out => hashScript(out.script) === hash) || tx.ins.some(input => { const prev = this.transactions.get(Buffer.from(input.hash).reverse().toString('hex')); return prev && prev.tx.outs[input.index] && hashScript(prev.tx.outs[input.index].script) === hash; })).map(([txid, item]) => ({txid,height:item.height}));
  }
  async listUnspent(hash) { const outputs=[]; for (const [txid, {tx,height}] of this.transactions) for (let vout=0;vout<tx.outs.length;vout++) if (hashScript(tx.outs[vout].script)===hash && await rpc('gettxout',[txid,vout,true])) outputs.push({txid,outputIndex:vout,valueSat:tx.outs[vout].value,height}); return outputs; }
  async getTransactionMerkleProof(txid,height) { const block=await rpc('getblock',[await rpc('getblockhash',[height]),1]); const txIndex=block.tx.indexOf(txid); assert(txIndex>=0); return {blockHeight:height,txIndex}; }
  async refresh() {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      const height = await rpc('getblockcount'); let changed = height !== this.height;
      for (let h=this.height+1;h<=height;h++) { const block=await rpc('getblock',[await rpc('getblockhash',[h]),2]); for (const tx of block.tx) this.transactions.set(tx.txid,{tx:bitcoin.Transaction.fromHex(tx.hex),height:h}); }
      for (const txid of await rpc('getrawmempool')) if (!this.transactions.has(txid)) { await this.getTransaction(txid); changed = true; }
      this.height = height;
      if (changed) { for (const callback of this.headers) callback(height); for (const callbacks of this.scripts.values()) for (const callback of callbacks) callback(); }
    })();
    try { await this.refreshing; } finally { this.refreshing = undefined; }
  }
}
async function beignetNode(name, chain, primary) {
  const keys = deriveLightningKeysFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', `${name}-${Date.now()}`, LnCoinType.REGTEST);
  const features = FeatureFlags.empty();
  for (const feature of ['DATA_LOSS_PROTECT','STATIC_REMOTE_KEY','PAYMENT_SECRET','TLV_ONION','CHANNEL_TYPE','GOSSIP_QUERIES','ANCHOR_ZERO_FEE_HTLC','QUIESCE','SPLICE','ROUTE_BLINDING','SHUTDOWN_ANY_SEGWIT','SIMPLE_CLOSE','DUAL_FUND']) features.setOptional(Feature[feature]);
  const storage = new SqliteStorage(path.join(run, `${name}.sqlite`)); storage.open();
  const primaryId = primary?.ready.uri.split('@')[0];
  const node = new LightningNode({ ...keys, network:Network.REGTEST, enableNetworking:true, localFeatures:features, chainHashes:[REGTEST_CHAIN_HASH], zeroReserve:{advertise:true,role:'wallet'}, preferAnchors:true, storage, chainBackend:chain, directFunding:{ onion:false, relay:true, directPeer:true, policy: primary ? {liquidityPeer:primaryId,liquidityHost:'127.0.0.1',liquidityPort:primary.port,allowSplice:true,allowUnpairedSplice:true,unpairedSpliceDepth:3,allowZeroConf:false} : {} } });
  beignetNodes.push(node);
  node.on('error', error => fs.appendFileSync(path.join(run, `${name}.log`),String(error)+'\n'));
  node.on('log', event => fs.appendFileSync(path.join(run, `${name}.log`),JSON.stringify(event, (_,v) => typeof v==='bigint' ? v.toString() : v)+'\n'));
  for (const event of ['direct-funding:offer:declined','direct-funding:offer:failed','direct-funding:offer:accepted','direct-funding:offer:completed','channel:error']) node.on(event, value => fs.appendFileSync(path.join(run, `${name}.events`), JSON.stringify({event,value},(_,v)=>typeof v==='bigint'?v.toString():v)+'\n'));
  const port = await freePort(); await node.listen(port,'127.0.0.1');
  await node.startChainWatcher(); await node.startDirectFunding();
  if (primary) await node.connectPeer(primaryId,'127.0.0.1',primary.port);
  return {node,port,storage};
}
async function main() {
  assert.equal((await rpc('getblockchaininfo')).chain,'regtest','Refusing non-regtest chain');
  await rpc('createwallet',[rpcWallet]);
  const mining = await rpc('getnewaddress',[],true);
  await rpc('generatetoaddress',[101,mining]);
  const chain = new CoreChain(await rpc('getblockcount'));
  const interval = setInterval(() => chain.refresh().catch(error => fs.appendFileSync(path.join(run,'chain.log'),String(error)+'\n')),500);
  try {
    const primary = await Native.start('primary');
    const receiver = await Native.start('native-receiver',primary.ready.uri);
    const sender = await Native.start('native-sender');
    await rpc('sendtoaddress',[primary.ready.address,0.01],true);
    await rpc('sendtoaddress',[sender.ready.address,0.01],true);
    const jsPayer = await beignetNode('beignet-payer',chain);
    const coins=[];
    for (const kind of ['p2wpkh','p2tr']) {
      const coin=makeCoin(300000,kind); const address=bitcoin.address.fromOutputScript(coin.script,bitcoin.networks.regtest);
      coin.txidHex=await rpc('sendtoaddress',[address,0.003],true);
      coin.prevTx=bitcoin.Transaction.fromBuffer(await chain.getTransaction(coin.txidHex));
      coin.vout=coin.prevTx.outs.findIndex(out=>out.script.equals(coin.script)); assert(coin.vout>=0); coins.push(coin);
    }
    await rpc('generatetoaddress',[6,mining]); await chain.refresh();
    for (const coin of coins) coin.height=chain.transactions.get(coin.txidHex).height;
    for (const n of [primary,receiver,sender]) await n.call('sync');
    class RealCoinWallet extends FakeSenderWallet {
      async getTransaction(txid) { return chain.getTransaction(txid); }
      async spentOnChain(coin) { return !(await rpc('gettxout',[coin.txidHex,coin.vout,true])); }
      blockHeight() { return chain.height; }
    }
    const wallet = new RealCoinWallet(coins); wallet.signsProbes = true;
    const paymentStore = new DirectFundingPaymentStore({storage:jsPayer.storage});
    const payer = new DirectFundingSender({wallet,registry:jsPayer.node.getDirectFundingRegistry(),payments:paymentStore,chainHash:()=>chainHashForNetwork(Network.REGTEST),log:(action,data)=>fs.appendFileSync(path.join(run,'beignet-sender.log'),JSON.stringify({action,data})+'\n')});
    for (const [index,amount] of [100000,40000].entries()) {
      const request=await receiver.call('direct_funding_request',{amountSats:amount});
      const payment=await payer.send(request.request,{maxTotalFeeSat:10000n});
      assert(payment.fundingTxid,JSON.stringify(payment));
      await wait('Beignet payer funding in mempool',async()=> (await rpc('getrawmempool')).includes(payment.fundingTxid));
      await rpc('generatetoaddress',[6,mining]); await chain.refresh(); for (const n of [primary,receiver,sender]) await n.call('sync');
      const expected=index===0?100000:140000;
      const channel=await wait('native receiver exact credit',async()=> (await receiver.call('channels')).find(c=>c.isUsable&&c.valueSats===expected));
      assert.equal((await receiver.call('channels')).length,1);
      await wait('native receiver durable confirmation',async()=> (await receiver.call('direct_funding_payments')).some(p=>p.fundingTxid===payment.fundingTxid&&p.status==='Confirmed'));
      log(`Beignet ${coins[index].kind} payer -> native ${index?'splice':'new channel'}`,{txid:payment.fundingTxid,valueSats:channel.valueSats});
    }
    const jsReceiver=await beignetNode('beignet-receiver',chain,primary);
    for (const [index,amount] of [100000,40000].entries()) {
      const request=jsReceiver.node.mintDirectFundingRequest({host:'127.0.0.1',port:jsReceiver.port,amountSat:BigInt(amount)});
      const payment=await sender.call('direct_funding_send',{request:request.request,amountSats:amount,maxFeeSats:10000});
      assert(payment.fundingTxid,JSON.stringify(payment));
      await wait('native payer funding in mempool',async()=> (await rpc('getrawmempool')).includes(payment.fundingTxid));
      await rpc('generatetoaddress',[6,mining]); await chain.refresh(); await primary.call('sync'); await sender.call('sync');
      const expected=index===0?100000n:140000n;
      const channel=await wait('Beignet receiver exact credit',()=>jsReceiver.node.getChannelManager().listChannels().find(c=>c.getState()===ChannelState.NORMAL&&c.getFundingSatoshis()===expected));
      assert.equal(jsReceiver.node.getChannelManager().listChannels().length,1);
      log(`native payer -> Beignet ${index?'splice':'new channel'}`,{txid:payment.fundingTxid,valueSats:channel.getFundingSatoshis().toString()});
    }
  } finally { clearInterval(interval); }
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;}).finally(async()=>{
  for(const node of beignetNodes.reverse()) node.destroy();
  for(const node of nativeNodes.reverse()) await node.stop();
  fs.writeFileSync(path.join(run,'evidence.json'),JSON.stringify(evidence,null,2)+'\n');
  process.stdout.write(JSON.stringify({artifacts:run,checks:evidence.length})+'\n');
});
