#!/usr/bin/env node
'use strict';
// A bounded loopback controller for manual native UI qualification. The phone
// runs its ordinary screens; this process only supplies disposable regtest peers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const readline = require('node:readline');
const { randomBytes, createHash } = require('node:crypto');
const { execFileSync, spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const source = process.env.BEIGNET_SOURCE_DIR || path.resolve(root, '../../testing/beignet');
const binary = process.env.CHICORY_PRIMARY_BIN || path.join(root, 'tools/chicory-primary/target/debug/chicory-primary-local');
const primaryChainSource = 'rpc://polaruser:polarpass@127.0.0.1:43782';
const timeoutMs = 180000;
const output = process.env.CHICORY_IOS_UI_CONFIG || '/tmp/chicory-ios-ui-config.json';
const evidencePath = process.env.BEIGNET_EVIDENCE_FILE || '/tmp/chicory-ios-ui-evidence.json';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function btc(...args) {
  return execFileSync('docker', ['exec', 'bitcoin', 'bitcoin-cli', '-rpcport=43782',
    '-rpcuser=polaruser', '-rpcpassword=polarpass', '-rpcwallet=default', ...args],
    {encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024}).trim();
}
async function wait(name, read) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { if (await read()) return; await delay(500); }
  throw Error(name + ' timed out');
}
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function startPrimary(dataDir, port) {
  const child = spawn(binary, [dataDir, String(port), primaryChainSource], {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe'],
  });
  const pending = new Map();
  let serial = 0;
  let stderr = '';
  let readyResolve;
  let readyReject;
  const readyPromise = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const readyTimer = setTimeout(() => readyReject(new Error('Primary startup timed out')), timeoutMs);
  child.stderr.on('data', bytes => {
    stderr = (stderr + bytes.toString()).slice(-8000);
  });
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', line => {
    let message;
    try { message = JSON.parse(line); }
    catch { return; }
    if (message.ready === true) {
      clearTimeout(readyTimer);
      readyResolve(message);
      return;
    }
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) request.reject(new Error(message.error));
    else request.resolve(message.result);
  });
  const failed = error => {
    clearTimeout(readyTimer);
    readyReject(error);
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    pending.clear();
  };
  child.on('error', failed);
  const exited = new Promise(resolve => {
    child.once('close', (code, signal) => {
      failed(new Error(`Primary exited (${code ?? signal}): ${stderr}`));
      lines.close();
      resolve({ code, signal });
    });
  });
  const request = (method, fields = {}) => new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      reject(new Error('Primary is stopped'));
      return;
    }
    const id = ++serial;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Primary ${method} timed out`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(JSON.stringify({ id, method, ...fields }) + '\n', error => {
      if (!error) return;
      pending.delete(id);
      clearTimeout(timer);
      reject(error);
    });
  });
  try {
    const ready = await readyPromise;
    assert.match(ready.nodeId, /^0[23][0-9a-f]{64}$/);
    assert.match(ready.address, /^bcrt1/);
    return {
      ready, request, child,
      async stop() {
        if (child.exitCode === null && child.signalCode === null) {
          try { await request('stop'); }
          catch { child.kill('SIGTERM'); }
          child.stdin.end();
          const kill = setTimeout(() => child.kill('SIGKILL'), 15000);
          await exited;
          clearTimeout(kill);
        }
      },
    };
  } catch (error) {
    child.kill('SIGKILL');
    await exited;
    throw error;
  }
}


async function main() {
  assert.equal(JSON.parse(btc('getblockchaininfo')).chain, 'regtest');
  const restore = process.env.CHICORY_IOS_UI_RESTORE_DIR;
  const temp = restore ? fs.realpathSync(restore) : fs.mkdtempSync(path.join(os.tmpdir(), 'chicory-ios-ui-'));
  if (restore) {
    assert.equal(path.dirname(temp), fs.realpathSync(os.tmpdir()));
    assert.match(path.basename(temp), /^chicory-ios-ui-[A-Za-z0-9]+$/);
    assert.ok(fs.existsSync(path.join(temp, 'primary')) && fs.existsSync(path.join(temp, 'payer')));
  }
  const token = randomBytes(24).toString('hex');
  const port = restore ? Number(process.env.CHICORY_IOS_UI_RESTORE_PORT) : await freePort();
  assert.ok(Number.isSafeInteger(port) && port > 1024 && port < 65536);
  const apiPort = await freePort();
  const evidence = restore ? JSON.parse(fs.readFileSync(evidencePath, 'utf8')) : {scope:'normal-ios-ui-regtest',startedAt:new Date().toISOString(),
    primaryBinarySha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),operations:[]};
  const persist = () => fs.writeFileSync(evidencePath, JSON.stringify(evidence,null,2)+'\n',{mode:0o600});
  let primary;
  let payer;
  let stopped = false;
  let busy = false;
  let paidSats = evidence.operations.filter(x=>x.operation==='pay'||x.operation==='pay-intent').reduce((n,x)=>n+x.amountSats,0);
  let resolveDone;
  const done = new Promise(resolve => { resolveDone=resolve; });
  const server = http.createServer(async (req,res) => {
    res.setHeader('Content-Type','application/json');
    let ownsBusy = false;
    try {
      if (req.method !== 'POST' || req.headers['x-chicory-test-token'] !== token) {
        res.writeHead(403).end('{}'); return;
      }
      if (busy) { res.writeHead(409).end('{}'); return; }
      busy=true;
      ownsBusy=true;
      let bytes='';
      for await (const part of req) { bytes+=part.toString(); if(Buffer.byteLength(bytes)>65536) throw Error('Request too large'); }
      const body=JSON.parse(bytes||'{}');
      let result;
      if(req.url==='/state') {
        result={channels:primary ? await primary.request('channels') : [],
          balance:primary ? await primary.request('balance') : null,
          payerChannels:payer.listChannels().map(c=>({channelId:c.channelId,htlcUsable:c.htlcUsable}))};
      } else if(req.url==='/invoice') {
        assert.ok(Number.isSafeInteger(body.amountSats)&&body.amountSats>0&&body.amountSats<=50000);
        result=await primary.request('invoice',{amountSats:body.amountSats,description:'Native Chicory UI test'});
      } else if(req.url==='/pay') {
        assert.match(body.bolt11||'',/^lnbcrt/);
        const decoded=payer.decodeInvoice(body.bolt11);
        assert.ok(Number.isSafeInteger(decoded.amountSats)&&decoded.amountSats>0&&decoded.amountSats<=50000);
        assert.ok(paidSats+decoded.amountSats<=100000,'Fixture payment budget exceeded');
        paidSats+=decoded.amountSats;
        const paymentRecord={operation:'pay-intent',amountSats:decoded.amountSats,paymentHash:decoded.paymentHash,at:new Date().toISOString()};
        evidence.operations.push(paymentRecord);persist();
        const payment=await payer.payInvoiceSafe(body.bolt11,timeoutMs,1000);
        result={status:payment.status,paymentHash:decoded.paymentHash,amountSats:decoded.amountSats};
        if(payment.failureDescription) result.failureDescription=String(payment.failureDescription).slice(0,500);
        Object.assign(paymentRecord,{operation:'pay',...result,completedAt:new Date().toISOString()});persist();
      } else if(req.url==='/liquidity') {
        assert.ok(!evidence.operations.some(x=>x.operation==='liquidity'), 'One bounded UI capacity extension only');
        assert.match(body.channelId||'', /^[0-9a-f]{64}$/);
        const channels=await primary.request('channels');
        const home=channels.find(c=>c.channelId===body.channelId);
        assert.ok(home && home.isUsable && home.valueSats<=100000);
        assert.ok(!payer.listChannels().some(c=>c.channelId===home.channelId), 'Phone home only');
        evidence.operations.push({operation:'liquidity',channelId:home.channelId,amountSats:100000,at:new Date().toISOString()});persist();
        result=await primary.request('splice_in',{channelId:home.channelId,amountSats:100000});
      } else if(req.url==='/primary/stop') {
        assert.ok(primary);await primary.stop();primary=null;result={stopped:true};
      } else if(req.url==='/primary/start') {
        assert.ok(!primary);primary=await startPrimary(path.join(temp,'primary'),port);
        assert.equal(primary.ready.nodeId,evidence.providerNodeId);
        await payer.connectPeer(primary.ready.nodeId,'127.0.0.1',port);result={restarted:true};
      } else if(req.url==='/sync') {
        await primary.request('sync');await payer.refreshWallet();result={synced:true};
      } else if(req.url==='/finish') {
        evidence.completedAt=new Date().toISOString();persist();result={stopped:true};stopped=true;
      } else { throw Error('Unsupported UI qualification operation'); }
      res.end(JSON.stringify(result));
      if(stopped) resolveDone();
    } catch(error) {res.writeHead(400).end(JSON.stringify({error:String(error.message).slice(0,500)}));}
    finally {if(ownsBusy)busy=false;}
  });
  const lifetime=setTimeout(resolveDone,45*60*1000);
  try {
    primary=await startPrimary(path.join(temp,'primary'),port);
    if(restore) assert.equal(primary.ready.nodeId,evidence.providerNodeId);
    else evidence.providerNodeId=primary.ready.nodeId;
    const {BeignetNode}=require(path.join(source,'dist/cli/beignet-node.js'));
    payer=await BeignetNode.create({network:'regtest',dataDir:restore?fs.mkdtempSync(path.join(temp,'payer-session-')):path.join(temp,'payer'),allowMultipleInstances:true,
      electrumHost:'127.0.0.1',electrumPort:60001,electrumTls:false,listenPort:await freePort(),
      autoBootstrap:false,autoGossipSync:false,logger:{debug(){},info(){},warn(){},error(){}}});
    await payer.connectPeer(primary.ready.nodeId,'127.0.0.1',port);
    {
    if(!restore) btc('sendtoaddress',primary.ready.address,'0.02000000');
    btc('sendtoaddress',await payer.getNewAddress(),'0.01000000');btc('-generate','1');
    await wait('Funding',async()=>{await primary.request('sync');await payer.refreshWallet();
      return (await primary.request('balance')).spendableOnchainSats>=100000&&payer.getBalance().onchain>=1000000;});
    await payer.openChannel(primary.ready.nodeId,400000,0,2,false,false);
    await wait('Payer funding',()=>{const c=payer.listChannels().find(c=>c.fundingTxid);
      return c&&JSON.parse(btc('getrawmempool')).includes(c.fundingTxid);});
    btc('-generate','6');
    }
    await wait('Payer channel',async()=>{await primary.request('sync');await payer.refreshWallet();
      return payer.listChannels().some(c=>c.htlcUsable);});
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(apiPort,'127.0.0.1',resolve);});
    fs.writeFileSync(output,JSON.stringify({api:'http://127.0.0.1:'+apiPort,token,
      fixtureDirectory:temp,primaryUri:primary.ready.uri,electrum:{host:'127.0.0.1',port:60001,tls:false}},null,2)+'\n',{mode:0o600});
    evidence.operations.push({operation:restore?'restored-regtest-peers':'funded-regtest-peers',at:new Date().toISOString()});persist();
    console.log(JSON.stringify({ready:true,config:output,evidence:evidencePath,primaryUri:primary.ready.uri}));
    process.once('SIGINT',resolveDone);process.once('SIGTERM',resolveDone);
    await done;
  } finally {
    clearTimeout(lifetime);server.closeAllConnections();server.close();
    if(payer)await payer.gracefulShutdown(5000).catch(()=>{});
    if(primary)await primary.stop();
    evidence.cleanedUpAt=new Date().toISOString();persist();
    console.log(JSON.stringify({stopped:true,evidence:evidencePath}));
  }
}
main().catch(error=>{console.error(String(error.message));process.exitCode=1;});
