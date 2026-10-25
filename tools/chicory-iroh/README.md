# Optional Iroh transport for native LDK Node

This local tool forwards one ordered QUIC stream using ALPN `beignet/bolt8/1`
to an explicitly configured loopback TCP listener. Native LDK performs BOLT8
authentication and owns all Lightning keys, channels, payments, and persistence.
The bridge does not instantiate a Beignet node or interpret Lightning messages.

Requires Node 20.3 or newer and the pinned `@number0/iroh` 1.1.0 native addon:

```sh
cd tools/chicory-iroh
npm install
node bridge.cjs --identity /absolute/private/path/iroh.key \
  --port 9735 --node-id NATIVE_LDK_COMPRESSED_PUBLIC_KEY
```

The ready JSON contains the public endpoint id, direct addresses, and an Iroh
connection URI. Direct addresses are separate from that URI. Discovery and relays
are disabled by default. An explicit `--discovery` enables n0 address discovery;
`--default-relays` enables its production relay map, or repeat `--relay URL` for
up to four explicit relays. Explicit relay startup waits at most 10 seconds for
a usable home relay before returning its address. Relay reachability and the installed phone's Iroh
path require separate interoperability qualification. No relay success is claimed
by the direct local tests.

Local verification passed ten tests covering identity file checks, bounded
configuration, 512 KiB of ordered direct traffic, connection admission and
handshake timeout, ALPN/datagram rejection, relay readiness timeout, terminal
accept/refusal cleanup, nonzero CLI failure exit, and shutdown. A separate native LDK
BOLT8 test passed the authenticated handshake and decrypted native `init` over
the same direct bridge. These checks do not qualify phone payments or relays.

The installed portable wallet also passed six baseline checks over the direct
bridge, including JIT receipt, wallet restart, and an outgoing payment. Its
subsequent offline setup exposed a portable-runtime watchdog bug: eight seconds
after connecting, the wallet tests current HTLC admission rather than whether
reestablishment completed. A legitimate FFOR setup hold can therefore force a
reconnect on an already working channel. See the installed
[`portable/runtime.ts` watchdog](https://github.com/coreyphillips/beignet-portable-engine/blob/67bc9cf0ba3e55fa1e1d7ad73e360bb04321a62c/portable/runtime.ts#L644).
The integration report is tracked in
[Beignet issue 1872](https://github.com/coreyphillips/beignet/issues/1872).
For further qualification, let that initial watchdog expire while the restored
channel is stable and usable before beginning offline setup. This is a test
scheduling workaround; it does not fix the installed wallet. That failing run
does not establish Iroh offline-receive, public-relay, or native iOS success.

The endpoint identity is a separate random 32-byte file, created exclusively with
mode `0600` and synced before use. Existing files must have the same size, owner,
and mode. Symlinks and malformed files are refused. Back up this file to preserve
the transport address. Its contents are never printed. Lightning's own identity
remains the public key in the URI and is authenticated end to end by BOLT8.

Bounds: 32 total connections, 8 pending handshakes, 10-second handshake/TCP
deadline, 15-second write deadline, 120-second idle timeout, one bidirectional
stream per connection, no unidirectional streams or datagrams, 128 KiB QUIC
receive window, and 32 KiB application chunks. Both directions wait for writes
before reading more. Timed-out native handshakes retain their pending slot until
they actually terminate. The addon also has its own finite native buffers and
handshake limits, which this JavaScript wrapper does not replace. EOF or errors
close both directions. SIGINT/SIGTERM stops accepting and closes all connections.
An accept-loop failure, unexpected endpoint exhaustion, or failed admission
refusal closes the endpoint and its pending connections. Shutdown is bounded by
15 seconds and the command exits nonzero on transport or shutdown failure.
Embedded callers can observe `waitForShutdown()` as well as calling `close()`.

The endpoint id authenticates the transport, not the Lightning peer. A hostile
Iroh peer may consume the bounded admission capacity or send arbitrary bytes to
the selected local LDK port. LDK must retain its ordinary BOLT8 and peer limits.
The destination accepts only literal `127.0.0.1` or `::1`; there is no per-peer
destination selection. Local identity files and the configured native addon are
trusted. A compromised bridge can disrupt availability or redirect encrypted
traffic, but does not gain the native Lightning signing keys.

Run direct tests using a local installation or the already-installed addon:

```sh
IROH_BINDING_PATH=/absolute/path/to/node_modules/@number0/iroh npm test
```

The optional BOLT8 test additionally takes `LDK_TEST_BINARY` pointing to
`target/debug/examples/chicory-primary`, `LDK_TEST_CHAIN_SOURCE` for the local
regtest source, and optionally `BEIGNET_SOURCE_DIR`. It starts a disposable native
LDK wallet, imports only Beignet's pure BOLT8 codec for the test client, and checks
the authenticated native `init`. It does not claim wallet features, mine, fund,
or open a channel. Full negotiation belongs to the installed-phone fixture.

The implementation uses the public binding API from the MIT/Apache-2.0 licensed
[`iroh-ffi`](https://github.com/n0-computer/iroh-ffi) package. The ALPN and stream
convention were checked against Beignet's MIT-licensed
`src/lightning/transport/iroh-node.ts` and `iroh.ts`. This bridge is an independent
implementation; no channel engine or private wallet identity code is copied.
