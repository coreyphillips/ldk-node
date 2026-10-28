#!/usr/bin/env python3
"""Qualify native bgnq funding against an explicitly selected disposable regtest chain."""
import argparse, base64, json, os, pathlib, queue, socket, subprocess, tempfile, threading, time
import urllib.request, urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('--rpc-url', default=os.environ.get('BGNQ_RPC_URL'))
parser.add_argument('--primary-driver', type=pathlib.Path,
    help='Optional JavaScript JSONL driver for the primary, invoked with node; wallet endpoints stay native')
args = parser.parse_args()
if not args.rpc_url:
    parser.error('--rpc-url is required; use a disposable regtest chain')
if args.primary_driver:
    args.primary_driver = args.primary_driver.resolve()
    if not args.primary_driver.is_file():
        parser.error('--primary-driver must name an existing JavaScript driver')
url = urllib.parse.urlparse(args.rpc_url)
root = pathlib.Path(__file__).resolve().parents[1]
run = pathlib.Path(tempfile.mkdtemp(prefix='bgnq-regtest-'))
auth = base64.b64encode(f'{url.username}:{url.password}'.encode()).decode()
base = f'http://{url.hostname}:{url.port}'
wallet = 'bgnq-' + str(time.time_ns())

def rpc(method, params=None, use_wallet=False):
    request = urllib.request.Request(base + ('/wallet/' + wallet if use_wallet else ''),
        data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode(),
        headers={'Authorization':'Basic ' + auth,'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if body.get('error'):
        raise RuntimeError(body['error'])
    return body['result']

assert rpc('getblockchaininfo')['chain'] == 'regtest', 'Refusing non-regtest chain'
rpc('createwallet', [wallet])
mining = rpc('getnewaddress', use_wallet=True)
rpc('generatetoaddress', [101, mining])
processes = []

class Native:
    def __init__(self, name, primary=None):
        self.name, self.primary = name, primary
        self.path = run / name
        self.path.mkdir(exist_ok=True)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.start()
        processes.append(self)
    def start(self):
        self.seq = 0
        self.lines = queue.Queue()
        env = dict(os.environ)
        if self.primary:
            env['LFBW_PRIMARY_URI'] = self.primary
        driver = ['node', str(args.primary_driver)] if self.name == 'primary' and args.primary_driver else [str(root / 'target/debug/examples/chicory-primary')]
        command = driver + [str(self.path), str(self.port), args.rpc_url]
        self.proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=open(run / (self.name + '.stderr'), 'a'), text=True, bufsize=1)
        def read():
            for line in self.proc.stdout:
                try: self.lines.put(json.loads(line))
                except ValueError: pass
        threading.Thread(target=read, daemon=True).start()
        self.ready = self.lines.get(timeout=90)
        assert self.ready.get('ready'), self.ready
    def call(self, method, **params):
        self.seq += 1
        self.proc.stdin.write(json.dumps({'id':self.seq,'method':method,**params})+'\n')
        self.proc.stdin.flush()
        result = self.lines.get(timeout=180)
        if 'error' in result: raise RuntimeError((self.name, method, result['error']))
        return result['result']
    def stop(self):
        if self.proc.poll() is None:
            try: self.call('stop')
            except Exception: self.proc.terminate()
            self.proc.wait(timeout=30)
    def restart(self):
        self.stop()
        self.start()

def wait(label, fn, timeout=90):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = fn()
        if result: return result
        time.sleep(0.5)
    raise RuntimeError('Timed out: ' + label)

def sync(*nodes):
    for node in nodes: node.call('sync')

evidence = []
def passed(name, **details):
    evidence.append({'name':name,**details})
    print(json.dumps(evidence[-1]), flush=True)

try:
    primary = Native('primary')
    receiver = Native('receiver', primary.ready['uri'])
    sender = Native('sender')
    rpc('sendtoaddress', [primary.ready['address'], 0.01], True)
    rpc('sendtoaddress', [sender.ready['address'], 0.01], True)
    rpc('generatetoaddress', [6, mining])
    sync(primary, receiver, sender)
    assert receiver.call('channels') == []
    minted = receiver.call('direct_funding_request', amountSats=100000)
    paid = sender.call('direct_funding_send', request=minted['request'], amountSats=100000)
    assert paid['fundingTxid'] and paid['status'] in ['SignedPending','MempoolSeen','Confirmed'], paid
    wait('new channel transaction in mempool', lambda: paid['fundingTxid'] in rpc('getrawmempool'))
    passed('new channel direct funding reaches mempool', txid=paid['fundingTxid'], feeSats=paid['feeSats'])
    rpc('generatetoaddress', [6, mining])
    sync(primary, receiver, sender)
    channel = wait('new channel usable', lambda: next((c for c in receiver.call('channels') if c['isUsable']), None))
    assert channel['valueSats'] == 100000, channel
    assert receiver.call('balance')['onchainSats'] == 0
    passed('new channel has exact credit without onchain fallback', valueSats=channel['valueSats'])
    wait('received confirmed', lambda: any(p['status'] == 'Confirmed' for p in receiver.call('direct_funding_payments')))
    second = receiver.call('direct_funding_request', amountSats=40000)
    splice = sender.call('direct_funding_send', request=second['request'], amountSats=40000)
    assert splice['fundingTxid'] and splice['fundingTxid'] != paid['fundingTxid'], splice
    wait('splice transaction in mempool', lambda: splice['fundingTxid'] in rpc('getrawmempool'))
    before = receiver.call('channels')
    assert len(before) == 1 and before[0]['valueSats'] == 100000, before
    rpc('generatetoaddress', [6, mining])
    sync(primary, receiver, sender)
    grown = wait('splice locks', lambda: next((c for c in receiver.call('channels') if c['valueSats'] == 140000 and c['isUsable']), None))
    assert grown['userChannelId'] == channel['userChannelId']
    assert len(receiver.call('channels')) == 1
    passed('existing channel direct funding splices exact credit', valueSats=grown['valueSats'], txid=splice['fundingTxid'])
    repeat = sender.call('direct_funding_send', request=second['request'], amountSats=40000)
    assert repeat['fundingTxid'] == splice['fundingTxid']
    if args.primary_driver:
        primary_uri = primary.ready['uri']
        primary.restart()
        assert primary.ready['uri'] == primary_uri, 'Primary restart changed node identity'
    sender.restart()
    receiver.restart()
    sync(sender, receiver)
    if args.primary_driver:
        sync(primary)
        wait('restarted primary channel usable', lambda: any(c['isUsable'] and c['valueSats'] == 140000 for c in primary.call('channels')))
    repeat = sender.call('direct_funding_send', request=second['request'], amountSats=40000)
    assert repeat['fundingTxid'] == splice['fundingTxid']
    assert len(sender.call('direct_funding_payments')) == 2
    assert len(receiver.call('direct_funding_payments')) == 2
    passed('payment retry and both endpoint restarts preserve exactly two payments',
        **({'primaryRestarted': True, 'primaryIdentityPreserved': True} if args.primary_driver else {}))
finally:
    for node in reversed(processes): node.stop()
    (run / 'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({'artifacts':str(run),'checks':len(evidence)}), flush=True)
