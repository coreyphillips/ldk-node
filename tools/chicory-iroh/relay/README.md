# Forced public relay qualification

This local test adapter runs only the Iroh endpoint in a disposable Docker
network namespace. The installed Chicory portable engine, wallet-core, and
BOLT8 implementation remain unchanged on the host. Native LDK owns the channel
engine and signing keys. This container is a qualification tool, not a second
Lightning node or a deployment dependency.

The container installs an IPv4 and IPv6 UDP output gate before starting its
endpoint. The endpoint runs as UID 1000 with no effective, permitted, inheritable,
or ambient capabilities and
`NoNewPrivs=1`. All endpoint UDP is dropped except traffic to Docker's local DNS
service at `127.0.0.11`. Docker's trusted DNS forwarder runs outside that UID
rule and can resolve public relay names. The endpoint cannot change the rule,
become root, or contact a direct QUIC peer. Iroh relay connections use TCP.
No host firewall settings change.

The controller verifies exact rules and process privileges before connecting
and again before shutdown. It also records relay byte counters and rejects any
observed direct path. Path snapshots alone would not prove continuous relay
use. The privilege boundary and continuously installed rules supply that proof.
The Docker daemon, its DNS forwarder, the host controller, and the pinned native
addon are trusted. The endpoint's transport secret passes through a private
stdin pipe, is never logged, and does not contain native Lightning signing keys.

Each endpoint has a private temporary Docker network, at most eight connections
or unresolved native dials, 32 pending host requests, 64 pending container
requests, a 128 KiB receive window, and 32 KiB write chunks. A timed-out native
dial retains its admission slot until the native operation actually finishes.
The container has 512 MiB memory, two CPUs, 128 processes, a read-only root,
and a 16 MiB temporary filesystem. Cleanup closes the endpoint, removes the
container and network, and verifies their absence.

Build the locally pinned Linux addon image from the repository root:

```sh
docker build --pull=false -t chicory-iroh-relay-local:1.1.0 \
  tools/chicory-iroh/relay
```

The package lock pins `@number0/iroh` 1.1.0. The Dockerfile pins the Node Alpine
base image by digest. APK networking tools are resolved when that local image
is built; the evidence records the resulting immutable image id.

Run the isolated transport checks with a normally built regtest host:

```sh
CHICORY_TEST_PUBLIC_RELAY=1 \
IROH_BINDING_PATH=/absolute/path/to/node_modules/@number0/iroh \
LDK_TEST_BINARY=/absolute/path/to/chicory-primary-local \
LDK_TEST_CHAIN_SOURCE=tcp://REGTEST_ELECTRUM_HOST:PORT \
CHICORY_RELAY_EVIDENCE_FILE=/tmp/chicory-relay-transport.json \
node --test tools/chicory-iroh/relay.test.cjs \
  tools/chicory-iroh/relay-worker.test.cjs
```

These checks cover the installed URI parser, isolation rejection cases, native
dial cancellation bounds, 256 KiB of ordered bytes with an explicit public relay
URI, default discovery with no relay or direct hints, and authenticated BOLT8
with native LDK. The native host is fresh and unfunded. These checks neither
mine nor fund the chain.

The funded installed-wallet fixture uses the same isolation factory:

```sh
CHICORY_PRIMARY_BIN=/absolute/path/to/chicory-primary-local \
IROH_BINDING_PATH=/absolute/path/to/node_modules/@number0/iroh \
CHICORY_ENABLE_OFFLINE=1 CHICORY_TEST_OFFLINE=1 \
CHICORY_TEST_OFFLINE_CONCURRENT=1 \
CHICORY_TEST_IROH=1 CHICORY_TEST_IROH_RELAY=1 \
BEIGNET_EVIDENCE_FILE=/tmp/chicory-relay-wallet.json \
node scripts/chicory-portable-interop.cjs
```

Set `CHICORY_TEST_IROH_DISCOVERY=1` to omit the relay query from the primary URI
and use default endpoint discovery. Neither relay mode inserts the historical
nine-second offline setup delay. Coordinate this funded fixture with all other
users of its regtest chain. Its default Core RPC and Electrum settings refer to
the repository's local Docker fixture; use the documented environment variables
in the script to select another regtest instance.

The native iOS fixture uses its real native endpoint, not this container factory.
`CHICORY_TEST_IOS=1 CHICORY_TEST_IROH=1` supplies an explicit public relay URI to
the phone and leaves factory selection to its production wallet client. Combining
the iOS flag with the container relay flag is rejected because the isolation
proof does not apply to the native iOS process.

Add `CHICORY_TEST_IROH_PROVIDER_RELAY=1` to isolate the provider endpoint instead.
The test-only adapter in `isolated-provider-fixture.cjs` bridges one ordered raw
stream to the explicit native loopback listener. It allows eight connections,
waits for each write before reading more, uses 32 KiB chunks, a ten-second TCP
connection deadline, fifteen-second write deadlines and a two-minute idle bound.
Its container has the same endpoint UDP prohibition and empty capabilities.
This permits the native phone to use its production adapter while direct QUIC
between phone and provider is impossible. Cleanup verifies provider firewall
rules, bidirectional relay traffic, and removal of the container and network.
The standalone public-relay provider byte test passed, followed by all eleven
funded native iOS checks through the actual native phone endpoint. That run
covered concurrent offline receive, ordinary payments, provider restarts and
exactly one recovered credit, with no setup delay. The provider recorded four
relay sessions, blocked direct UDP, and verified container/network cleanup.
See [`ios-forced-relay.json`](../../../docs/qualification/ios-forced-relay.json).

## Same-key onion fallback

The installed wallet accepts only a v3 onion fallback carrying the same
Lightning public key as the Iroh primary. It rejects a different key, an ordinary
TCP fallback, or another Iroh fallback. BOLT8 authenticates that same node key
after transport selection.

The separate fallback fixture creates an ephemeral Tor hidden service pointing
to the native listener and then stops the primary's Iroh endpoint. The unchanged
wallet must use its persisted onion fallback, saved through the public
`updatePrimary(primaryUri, fallbackUri)` settings API. Tor keys stay in disposable tmpfs.
Its SOCKS port is published only on host loopback. The test records attempted
Iroh dials and rejects any successful Iroh connection.

The portable host owns destination routing. Its bounded `tor-socket.cjs` adapter
accepts only this exact onion and port, performs the SOCKS connection outside the
engine, allows eight pending/live connections, and caps buffered writes at
256 KiB. Late dial results are closed after cancellation. The native iOS fallback
mode supplies neither this adapter nor a SOCKS override; the production phone
uses its own native Iroh and nitro-tor components. The fixture authorizes one
exact same-key onion pair in the simulator harness before updating settings.

```sh
docker build --pull=false -t chicory-iroh-tor-local:1 tools/chicory-iroh/tor
CHICORY_TEST_TOR_FALLBACK=1 node --test tools/chicory-iroh/tor.test.cjs

CHICORY_PRIMARY_BIN=/absolute/path/to/chicory-primary-local \
IROH_BINDING_PATH=/absolute/path/to/node_modules/@number0/iroh \
CHICORY_ENABLE_OFFLINE=1 CHICORY_TEST_OFFLINE=1 \
CHICORY_TEST_OFFLINE_CONCURRENT=1 \
CHICORY_TEST_IROH=1 CHICORY_TEST_IROH_FALLBACK=1 \
BEIGNET_EVIDENCE_FILE=/tmp/chicory-onion-fallback-wallet.json \
node scripts/chicory-portable-interop.cjs
```

Tor bootstrap is bounded to three minutes. The standalone ordered-byte test
allows up to two additional minutes for descriptor publication. The funded
fixture retains the wallet's actual transport timeouts and reconnect behavior.
The Tor image pins Tor 0.4.9.14 and the same Node Alpine base digest.

The installed wallet passed all eleven funded checks over forced public relay
transport with its original installed engine and no artificial offline setup
delay. The test covers pairing, 19,880-sat net JIT receipt, wallet restart,
outgoing payment, an active concurrent offline reservation, ordinary payments
while that reservation exists, a 5,000-sat external payment while the phone is
stopped, provider restarts, and two phone reopens with exactly one recovered
credit and one completed Activity entry. All four isolated endpoint containers
and networks were removed. See
[`wallet-qualification.json`](wallet-qualification.json) for hashes and evidence.
The existing installed-wallet JIT Activity amount discrepancy is unchanged:
its row reports gross 20,000 sats, while the exact committed balance is 19,880.

The first funded discovery run passed its six baseline checks, then exposed the
shared-input fee audit defect already tracked in
[Beignet issue 359](https://github.com/coreyphillips/beignet/issues/359). The native
splice paid 504 sats at 508 sat/kw, which covers its 992 WU witness shape. The
installed receiver audited the shared input with the conservative 386 WU funding
estimate and incorrectly required 505 sats. The local client fix uses 382 WU for
the attainable low-R shared-input audit minimum, preserves the 386 WU funding
reserve and cryptographic witness checks, and rejects offers below that minimum.
The targeted Beignet suites passed 644 tests. BOLT 2 separates the
[`tx_complete` minimum-fee check](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-tx_complete-message)
from the sender's actual witness fee responsibility in
[`tx_signatures`](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-tx_signatures-message).
This pre-signature check is not a final transaction fee audit.

The corrected locally installed client then passed all eleven funded checks
using default discovery, with a bare endpoint URI and no relay or direct-address
hints. It used the same enforced relay isolation and no setup delay. The final
balance was 22,080 sats, including exactly one recovered 5,000-sat offline credit
and one completed Activity row. Four endpoint containers and networks were
removed. The installed engine hash and all checks are retained in
[`discovery-wallet-qualification.json`](discovery-wallet-qualification.json).

Native iOS then passed all eleven funded checks through its persisted same-key
onion fallback while the provider Iroh endpoint was stopped. It used the actual
native Iroh and nitro-tor adapters, with no host factory or SOCKS override and no
setup delay. The final balance was 22,080 sats with exactly one recovered offline
credit. The remote Tor container and network were removed and the isolated app
was terminated. See
[`ios-onion-fallback.json`](../../../docs/qualification/ios-onion-fallback.json).

The portable host also passed all eleven funded fallback checks with its bounded
host adapter, five unsuccessful Iroh attempts and no successful Iroh connection.
The exact final balance was 22,080 sats, including one recovered offline credit.
Both its Tor container and network were removed. See
[`onion-fallback.json`](../../../docs/qualification/onion-fallback.json).
Its real Tor ordered-byte check and three destination/buffering/cancellation
regressions passed as well. Two earlier fixture-only setup failures are retained
in the local test logs: the initial harness used an unsupported create-wallet
argument, then omitted the portable host's required onion routing adapter. The
successful run uses the public settings API and real host SOCKS transport.

The six passing relay checks and public transport evidence are retained in
[`qualification.json`](qualification.json). Direct address values are omitted;
the record retains their count, exact firewall rules, empty capability sets,
image id, native binary hash, bidirectional relay counters, and verified cleanup.
