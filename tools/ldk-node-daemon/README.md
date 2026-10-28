# Native LDK Node daemon

This private administration process runs one persistent LDK Node with the local
Chicory protocol implementation. The Umbrel manager supervises it over stdin and
stdout. There is no administration HTTP listener, Beignet primary process, or
shared Lightning key with the Iroh transport bridge.

## Build and start

Rust 1.89 or later and a Unix host are required. The separate workspace avoids
activating the root library's test-only Lightning features. Keep both native
dependency patches in this manifest when embedding the library elsewhere.

```sh
cargo build --release --locked --manifest-path tools/ldk-node-daemon/Cargo.toml
tools/ldk-node-daemon/target/release/ldk-node-daemon --config /absolute/path/node.json
```

Use a private directory with mode `0700` and a configuration file with mode `0600`.
The configuration must select the network explicitly. This mainnet example uses
an operator-owned Bitcoin Core backend:

```json
{
  "network": "bitcoin",
  "data_dir": "/data/wallets/primary/native",
  "listen_address": "0.0.0.0:9735",
  "alias": "LDK primary",
  "chain_source": {
    "type": "bitcoind",
    "host": "bitcoin",
    "port": 8332,
    "user": "replace-with-rpc-user",
    "password": "replace-with-rpc-password"
  },
  "chicory": {
    "enabled": false,
    "flat_fee_sat": 100,
    "fee_ppm": 1000,
    "max_client_funding_sats": 500000,
    "max_total_fronted_sats": 2000000
  }
}
```

Other network values are `testnet`, `signet`, and `regtest`. Backend alternatives
are `{"type":"electrum","url":"ssl://host:50002"}` and
`{"type":"esplora","url":"https://host/api"}`. Do not include credentials in
these URLs. Configuration fields are strict; unknown fields fail startup. The former
`offline_enabled` option and `offline_status` command have been removed. Remove
that option from existing manager-generated configurations before starting this
version; offline receiving is no longer supported.

Provider funding requires an explicit opt-in. The provider uses confirmed inputs,
bounded funding allocation, a
six-confirmation inbound splice floor, and private stable funding keys for newly
created compatible homes. See [the protocol documentation](../../docs/chicory-primary.md)
for the state machine, recovery rules, backend fee policy, and qualification.

The daemon verifies the backend genesis before loading keys, binds the directory
to its network, and takes an exclusive process lock. A directory with older
unbound native state requires an explicit migration; it is never silently reused.
Keep the whole native directory for backups. Do not copy or restore a live store,
run two copies of one Lightning identity, or restore an obsolete channel snapshot.

## Administration contract

Each request is one newline-terminated JSON object, at most 256 KiB:

```json
{"id":"balance-1","method":"balance","params":{}}
```

The response has the same `id` and either `result` or
`error: {"code":"operation_failed","message":"..."}`. IDs are nonempty strings
up to 64 bytes or nonnegative safe JSON integers. Monetary inputs accept exact
safe JSON integers or decimal strings. Monetary outputs above `2^53 - 1` use
decimal strings. The ready notification is
`{"event":"ready","node_id":"...","network":"bitcoin","listen_address":"...","capabilities":[...]}`.
Only JSONL is written to stdout; startup diagnostics go to stderr and native logs
stay in the data directory. Closing stdin stops the node cleanly.

| Method | Parameters | Result |
| --- | --- | --- |
| `info` | none | Identity, network, alias, sync heights/timestamps, provider policy, capabilities |
| `balance` | none | On-chain total/spendable, Lightning total, anchor reserve, in satoshis |
| `channels` | none | IDs, counterparty, funding outpoint, capacities, readiness and confirmations |
| `peers` | none | Identity, address, connection and persistence status |
| `payments` | none | At most 2,000 recent public payment summaries, with status, amount and fee |
| `address` | none | `{address}` |
| `invoice` | optional `amount_msat`, `description`, `expiry_secs` | `{invoice}`; default expiry 3,600 seconds, maximum seven days |
| `pay` | `invoice`, optional `amount_msat` | `{id}` of the submitted BOLT11 payment |
| `estimate_onchain` | `address`, either `amount_sats` or `send_all:true`, optional `fee_rate_sat_per_kwu` | `{fee_sats,retains_channel_reserves:true}` |
| `send_onchain` | same as estimate | `{txid,broadcast}`; broadcast is `accepted`, `rejected` or `unknown` |
| `connect` | `node_id`, `address` | `{accepted:true}`, with reconnect persistence |
| `disconnect` | `node_id` | `{accepted:true}` |
| `open` | `node_id`, `address`, `amount_sats` | `{user_channel_id}` |
| `close` | `channel_id`, `counterparty_node_id`, optional `force` | `{accepted:true}` |
| `splice_in` | `channel_id`, `counterparty_node_id`, `amount_sats` | `{accepted:true}` |
| `splice_out` | same plus `address` | `{accepted:true}` |
| `sync` | none | `{synced:true}` |
| `events` | none | At most 2,048 durable public event records with sequence and timestamp |
| `stop` | none | `{stopped:true}`, followed by process exit |

Mutation success acknowledges submission, not final settlement. Track channel,
payment, and event state afterwards. Every Bitcoin send retains anchor reserves.
Manual opens, splices, and sends use `Node::with_chicory_wallet_operation` to
exclude simultaneous JIT funding. Pending native funding continues to exclude
new operations after the initiating call returns.

Request IDs correlate responses; they are not durable idempotency keys. If a
response is lost, reconcile payments, transactions and channels before deciding
what to do. Never automatically repeat a financial request. A rejected or unknown
broadcast still returns its transaction ID and `retry_safe:false`, because the
wallet has attempted that transaction. A payment ID is not proof of settlement.

Events are persisted before acknowledging the native event queue. A crash between
these writes can repeat an event, so the log is at least once. It is an activity
view rather than an accounting authority. A failed history write stops the native
node and emits `event_persistence_failed`. The manager must stop issuing commands
and surface that fault.

## Trust boundaries and validation

The supervising manager must authenticate operators, authorize requests, protect
the pipe and configuration, bound outstanding requests, and protect its own HTTP
surface. Any process able to read the private native store can steal wallet keys.
Chain backends are trusted for chain information; genesis validation prevents an
accidental network mismatch and does not establish backend honesty. Authenticated
Lightning peers remain untrusted, with protocol limits enforced by the library.

The daemon contains no new cryptographic protocol or unsafe Rust. The native
library owns signing, channel state, persistence and chain recovery. Private
administrative files reject leaf symlinks and are written by fsync and atomic
rename under the exclusive directory lock. A privileged or same-user attacker who
can replace ancestor directories is outside this file isolation boundary.

```sh
cargo test --locked --manifest-path tools/ldk-node-daemon/Cargo.toml
```

Tests cover strict configuration, explicit network binding, duplicate-process
exclusion, precision, bounded request frames, private file handling, genesis
verification before key loading, event redaction, and failed event writes. The
library separately tests manual/JIT exclusion. Fuzzing
and funded interoperability procedures remain in the protocol documentation.
