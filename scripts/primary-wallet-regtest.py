#!/usr/bin/env python3
"""Runs funded primary-wallet checks using disposable local regtest node stores."""

import argparse, base64, json, os, pathlib, queue, socket, subprocess, tempfile, threading, time, urllib.request, urllib.error, urllib.parse
parser = argparse.ArgumentParser(description='Disposable primary wallet interoperability on an existing regtest chain')
parser.add_argument('--provider', choices=['ldk', 'beignet'], default='ldk')
parser.add_argument('--rpc-url', default=os.environ.get('LFBW_REGTEST_RPC_URL'))
parser.add_argument('--electrum-url', default='tcp://127.0.0.1:60001')
parser.add_argument('--client-chain-url', help='Optional Electrum endpoint for the native client')
parser.add_argument('--beignet-root', type=pathlib.Path)
parser.add_argument('--faucet-wallet', default='default')
args = parser.parse_args()
if not args.rpc_url:
    parser.error('--rpc-url or LFBW_REGTEST_RPC_URL is required')
if args.provider == 'beignet' and (not args.beignet_root):
    parser.error('--beignet-root is required for Beignet')
url = urllib.parse.urlparse(args.rpc_url)
ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = pathlib.Path(tempfile.mkdtemp(prefix='lfbw-native-regtest-'))
AUTH = base64.b64encode(f'{url.username}:{url.password}'.encode()).decode()
BASE = f'http://{url.hostname}:{url.port}'
wallet = 'lfbw-client-' + str(int(time.time()))

def rpc(method, params=None, w=False):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    req = urllib.request.Request(BASE + ('/wallet/' + (w if isinstance(w, str) else wallet) if w else ''), data=body, headers={'Authorization': 'Basic ' + AUTH, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            v = json.load(f)
    except urllib.error.HTTPError as e:
        raise RuntimeError(e.read().decode())
    if v.get('error'):
        raise RuntimeError(v['error'])
    return v['result']
if rpc('getblockchaininfo')['chain'] != 'regtest':
    raise RuntimeError('Refusing to fund a chain that is not regtest')
rpc('createwallet', [wallet])
rpc('settxfee', [1e-05], True)
mining = rpc('getnewaddress', w=True)
rpc('sendtoaddress', {'address': mining, 'amount': 0.03, 'fee_rate': 2}, args.faucet_wallet)
rpc('generatetoaddress', [1, mining], True)
processes = []

class Native:

    def __init__(self, name, primary=None, listen_port=None):
        self.name = name
        self.lines = queue.Queue()
        self.seq = 0
        port = listen_port
        if port is None:
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
        self.port = port
        self.path = RUN / name
        self.path.mkdir(exist_ok=True)
        env = dict(os.environ)
        if name == 'legacy-client':
            env['LFBW_DISABLE_PROVIDER'] = '1'
        if primary:
            env['LFBW_PRIMARY_URI'] = primary
        command = [str(ROOT / 'target/debug/examples/chicory-primary'), str(self.path), str(port), args.client_chain_url if primary and args.client_chain_url else args.rpc_url]
        if name == 'primary' and args.provider == 'beignet':
            env['BEIGNET_ROOT'] = str(args.beignet_root.resolve())
            env['LFBW_ELECTRUM_URL'] = args.electrum_url
            command = ['node', str(ROOT / 'scripts/primary-wallet-beignet.cjs'), str(self.path), str(port)]
        self.proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(RUN / (name + '.stderr'), 'w'), text=True, bufsize=1)
        processes.append(self)

        def read():
            for line in self.proc.stdout:
                try:
                    self.lines.put(json.loads(line))
                except ValueError:
                    pass
        threading.Thread(target=read, daemon=True).start()
        self.ready = self.lines.get(timeout=60)
        assert self.ready.get('ready'), self.ready

    def call(self, method, **params):
        self.seq += 1
        self.proc.stdin.write(json.dumps({'id': self.seq, 'method': method, **params}) + '\n')
        self.proc.stdin.flush()
        v = self.lines.get(timeout=65)
        if 'error' in v:
            raise RuntimeError((self.name, method, v['error']))
        return v['result']

    def close(self):
        if self.proc.poll() is None:
            try:
                self.call('stop')
            except Exception:
                self.proc.terminate()
            self.proc.wait(timeout=20)

def wait(label, condition, seconds=90):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = condition()
        if value:
            return value
        time.sleep(0.5)
    raise RuntimeError('timeout ' + label)

def funding_seen(node):
    for channel in node.call('channels'):
        if channel.get('fundingTxid'):
            try:
                return rpc('getrawtransaction', [channel['fundingTxid']])
            except RuntimeError:
                pass
    return None

def spendable_at_least(node, amount_sats):
    node.call('sync')
    return node.call('balance')['spendableOnchainSats'] >= amount_sats
try:
    primary = Native('primary')
    sender = Native('sender')
    client = Native('client', primary.ready['uri'])
    rpc('sendtoaddress', [primary.ready['address'], 0.01], True)
    rpc('sendtoaddress', [sender.ready['address'], 0.01], True)
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, sender, client]:
        node.call('sync')
    open_id = '184467440737095516170'
    opened = sender.call('open', nodeId=primary.ready['nodeId'], address='127.0.0.1:' + str(primary.port), amountSats=500000, userChannelId=open_id)
    assert opened['userChannelId'] == open_id, opened
    wait('sender funding', lambda: funding_seen(sender))
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, sender, client]:
        node.call('sync')
    wait('sender channel', lambda : any((c['isUsable'] for c in sender.call('channels'))))
    quote = client.call('quote_primary', nodeId=primary.ready['nodeId'], amountSats=20000)
    assert quote['feeMsat'] == 120000, quote
    try:
        client.call('receive_primary', nodeId=primary.ready['nodeId'], amountSats=20000, maxFeeMsat=1)
        raise AssertionError('fee refusal absent')
    except RuntimeError as e:
        assert 'liquidity' in str(e).lower() or 'fee' in str(e).lower(), str(e)
    invoice = client.call('receive_primary', nodeId=primary.ready['nodeId'], amountSats=20000, maxFeeMsat=quote['feeMsat'])['bolt11']
    sender.call('pay', bolt11=invoice)
    received = wait('JIT receive', lambda : next((p for p in client.call('payments') if p['direction'] == 'Inbound' and p['status'] == 'Succeeded'), None))
    assert received['amountMsat'] == 19880000, received
    balance = client.call('balance')
    assert balance['lightningSats'] == 19880, balance
    outgoing = primary.call('invoice', amountSats=1000)['bolt11']
    client.call('pay', bolt11=outgoing)
    wait('client send', lambda : any((p['direction'] == 'Outbound' and p['status'] == 'Succeeded' for p in client.call('payments'))))
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, client]:
        node.call('sync')
    rpc('sendtoaddress', [client.ready['address'], 0.0005], True)
    rpc('generatetoaddress', [6, mining], True)
    client.call('sync')
    channel = client.call('channels')[0]
    client.call('splice_in', channelId=channel['channelId'], amountSats=40000)
    wait('splice in funding', lambda : len(rpc('getrawmempool')) > 0)
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, client]:
        node.call('sync')
    wait('splice in usable', lambda : any((c['isUsable'] and c['valueSats'] > channel['valueSats'] for c in client.call('channels'))))
    channel = client.call('channels')[0]
    address = rpc('getnewaddress', w=True)
    client.call('splice_out', channelId=channel['channelId'], address=address, amountSats=5000)
    wait('splice out funding', lambda : len(rpc('getrawmempool')) > 0)
    splice_txid = wait('splice payment', lambda: next((txid for txid in rpc('getrawmempool') if any(output.get('scriptPubKey', {}).get('address') == address for output in rpc('getrawtransaction', [txid, True])['vout'])), None))
    transaction = client.call('transaction', txid=splice_txid)
    assert any((output['address'] == address and output['valueSats'] == 5000 for output in transaction['outputs'])), transaction
    input_total = 0
    for tx_input in transaction['inputs']:
        previous = client.call('transaction', txid=tx_input['txid'])
        input_total += previous['outputs'][tx_input['vout']]['valueSats']
    transaction_fee = input_total - sum((output['valueSats'] for output in transaction['outputs']))
    assert transaction_fee > 0
    assert client.call('transaction_status', txid=splice_txid) == {'confirmed': False}
    try:
        client.call('transaction_status', txid='00' * 32)
        raise AssertionError('unknown transaction reported a confirmation status')
    except RuntimeError:
        pass
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, client]:
        node.call('sync')
    assert round(rpc('getreceivedbyaddress', [address, 1], True) * 100000000) == 5000
    confirmed_block = rpc('getblock', [rpc('getrawtransaction', [splice_txid, True])['blockhash']])
    expected_status = {'confirmed': True, 'blockHash': confirmed_block['hash'], 'height': confirmed_block['height'], 'timestamp': confirmed_block['time']}
    wait('authoritative splice confirmation', lambda: client.call('transaction_status', txid=splice_txid) == expected_status)
    before = client.call('balance')
    client.close()
    client = Native('client', primary.ready['uri'])
    client.call('sync')
    wait('reopen channel', lambda : any((c['isUsable'] for c in client.call('channels'))))
    after = client.call('balance')
    assert before == after, (before, after)
    assert client.call('transaction_status', txid=splice_txid) == expected_status
    deposit_client = Native('deposit-client', primary.ready['uri'])
    rpc('sendtoaddress', [deposit_client.ready['address'], 0.0005], True)
    rpc('generatetoaddress', [6, mining], True)
    wait('confirmed deposit client funds', lambda: spendable_at_least(deposit_client, 50000))
    deposit_client.call('open', nodeId=primary.ready['nodeId'], address='127.0.0.1:' + str(primary.port), amountSats=48200, userChannelId='184467440737095516172')
    try:
        deposit_client.call('quote_primary', nodeId=primary.ready['nodeId'], amountSats=100000)
        raise AssertionError('pending primary channel accepted a new receive quote')
    except RuntimeError as error:
        assert 'liquidity' in str(error).lower(), str(error)
    wait('deposit client funding', lambda: funding_seen(deposit_client))
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, sender, deposit_client]:
        node.call('sync')
    existing_channel = wait('deposit client channel', lambda: next((channel for channel in deposit_client.call('channels') if channel['isUsable']), None))
    assert existing_channel['valueSats'] == 48200, existing_channel
    deposit_client.close()
    deposit_client = Native('deposit-client', primary.ready['uri'])
    deposit_client.call('sync')
    wait('deposit client restart', lambda: any(channel['isUsable'] for channel in deposit_client.call('channels')))
    deposit_quote = deposit_client.call('quote_primary', nodeId=primary.ready['nodeId'], amountSats=100000)
    assert deposit_quote['feeMsat'] == 200000, deposit_quote
    deposit_invoice = deposit_client.call('receive_primary', nodeId=primary.ready['nodeId'], amountSats=100000, maxFeeMsat=deposit_quote['feeMsat'])['bolt11']
    sender.call('pay', bolt11=deposit_invoice)
    wait('deposit client JIT splice', lambda: len(rpc('getrawmempool')) > 0)
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, sender, deposit_client]:
        node.call('sync')
    deposit_received = wait('JIT receive above original capacity after restart', lambda: next((payment for payment in deposit_client.call('payments') if payment['direction'] == 'Inbound' and payment['status'] == 'Succeeded' and payment['amountMsat'] == 99800000), None))
    deposit_channels = deposit_client.call('channels')
    assert len(deposit_channels) == 1, deposit_channels
    assert deposit_channels[0]['valueSats'] > existing_channel['valueSats'], deposit_channels
    large_send_invoice = primary.call('invoice', amountSats=60000)['bolt11']
    deposit_client.call('pay', bolt11=large_send_invoice)
    wait('send above original channel capacity', lambda: any(payment['direction'] == 'Outbound' and payment['status'] == 'Succeeded' and payment['amountMsat'] == 60000000 for payment in deposit_client.call('payments')))
    provider_key, provider_port = primary.ready['nodeId'], primary.port
    primary.close()
    primary = Native('primary', listen_port=provider_port)
    assert primary.ready['nodeId'] == provider_key, 'provider identity changed on restart'
    primary.call('sync')
    for node in [client, sender, deposit_client]:
        node.call('connect', nodeId=provider_key, address='127.0.0.1:' + str(provider_port))
    wait('deposit client reestablished', lambda: any(channel['isUsable'] for channel in deposit_client.call('channels')))
    deposit_client.call('receive_primary', nodeId=provider_key, amountSats=100000, maxFeeMsat=deposit_quote['feeMsat'])
    # Establish a channel without the primary policy, then select the same peer
    # after restart. Its original negotiated limit must not silently change.
    legacy_client = Native('legacy-client')
    rpc('sendtoaddress', [legacy_client.ready['address'], 0.0005], True)
    rpc('generatetoaddress', [6, mining], True)
    wait('legacy client deposit', lambda: spendable_at_least(legacy_client, 50000))
    legacy_client.call('open', nodeId=provider_key, address='127.0.0.1:' + str(provider_port), amountSats=48200, userChannelId='184467440737095516173')
    wait('legacy client funding', lambda: funding_seen(legacy_client))
    rpc('generatetoaddress', [6, mining], True)
    for node in [primary, legacy_client]:
        node.call('sync')
    wait('legacy client channel', lambda: any(channel['isUsable'] for channel in legacy_client.call('channels')))
    legacy_client.close()
    legacy_client = Native('legacy-client', primary.ready['uri'])
    legacy_client.call('sync')
    wait('legacy client restart', lambda: any(channel['isUsable'] for channel in legacy_client.call('channels')))
    for method in ['quote_primary', 'receive_primary']:
        try:
            legacy_client.call(method, nodeId=provider_key, amountSats=100000, maxFeeMsat=200000)
            raise AssertionError('legacy channel accepted an undeliverable receive')
        except RuntimeError as error:
            assert 'amount' in str(error).lower(), str(error)
    consumed_id = '184467440737095516171'
    try:
        sender.call('open', nodeId='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', address='127.0.0.1:0', amountSats=25000, userChannelId=consumed_id)
        raise AssertionError('unreachable channel open unexpectedly succeeded')
    except RuntimeError as error:
        assert 'connect' in str(error).lower(), str(error)
    sender.close()
    sender = Native('sender')
    sender.call('sync')
    assert any(channel['userChannelId'] == open_id for channel in sender.call('channels'))
    for duplicate_id in [open_id, consumed_id]:
        try:
            sender.call('open', nodeId=primary.ready['nodeId'], address='127.0.0.1:' + str(primary.port), amountSats=25000, userChannelId=duplicate_id)
            raise AssertionError('duplicate open identity accepted after restart')
        except RuntimeError as error:
            assert 'channel' in str(error).lower(), str(error)
    evidence = {'provider': args.provider, 'checks': ['jit-quote', 'fee-ceiling-refusal', 'jit-receive-net-19880', 'lightning-send-1000', 'deposit-splice-in-40000', 'splice-out-5000-at-requested-rate', 'backend-transaction-and-parent-lookup', 'backend-mempool-and-confirmed-status', 'unknown-transaction-status-refused', 'confirmed-status-after-restart', 'wallet-restart', 'supplied-channel-id', 'open-id-replay-refused-after-restart', 'jit-receive-100000-after-48200-open-and-restart', 'lightning-send-60000-above-original-capacity', 'existing-channel-policy-route', 'provider-identity-and-policy-after-restart', 'legacy-channel-oversized-quote-and-invoice-refused', 'pending-primary-quote-refused'], 'quote': quote, 'received': received, 'depositFirstQuote': deposit_quote, 'depositFirstReceived': deposit_received, 'depositFirstOpeningSats': existing_channel['valueSats'], 'depositFirstFinalCapacitySats': deposit_channels[0]['valueSats'], 'spliceFeeSats': transaction_fee, 'spliceConfirmation': expected_status, 'finalBalance': after, 'directory': str(RUN)}
    (RUN / 'result.json').write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence), flush=True)
finally:
    for node in reversed(processes):
        try:
            node.close()
        except Exception:
            node.proc.kill()
    rpc('unloadwallet', [wallet])
