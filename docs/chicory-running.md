# Running a local native primary for Chicory

This branch provides an opt-in native provider through `Builder::set_chicory_service`.
The existing `chicory-primary` example is deliberately regtest-only. The library
accepts an explicit Bitcoin network and matching chain backend. The interoperability
evidence is from regtest; it does not establish production or mainnet readiness.
Read [the compatibility record](chicory-primary.md) for the exact tested scope and
remaining limitations before using persistent wallets.

## Build and preserve the native dependency patches

From this checkout:

```sh
cargo build --locked --features chicory --example chicory-primary
```

For an application outside this workspace, Cargo does not inherit a dependency's
`[patch]` table. Its top-level `Cargo.toml` must select both local native forks:

```toml
[package]
name = "chicory-primary-local"
version = "0.1.0"
edition = "2021"

[dependencies]
ldk-node = { path = "/absolute/path/to/ldk-node", features = ["chicory"] }

[patch.crates-io]
lightning = { path = "/absolute/path/to/ldk-node/vendor/lightning" }
lightning-liquidity = { path = "/absolute/path/to/ldk-node/vendor/lightning-liquidity" }
```

The patches are required for channel behavior and persisted safety state, not
only custom message parsing. Do not replace them with unmodified registry crates
when opening this branch's database. Keep the application lockfile and the local
source revision together.

## Configure a node through the public builder

This Rust program uses the standard software signer and persistent node store.
Set an absolute `LDK_DATA_DIR`, explicit `LDK_NETWORK`, and the four `LDK_RPC_*`
variables for a Bitcoin Core backend on the same network. RPC credentials are
read from the environment and are not printed. `LDK_LISTEN` defaults to loopback;
set it explicitly when direct remote TCP connections are needed. Each data
directory belongs to one running node and one network.

```rust
use std::error::Error;
use std::io::{self, BufRead};
use std::path::Path;
use ldk_node::bitcoin::Network;
use ldk_node::chicory::{JitServiceConfig, OfflineReceiveConfig};
use ldk_node::Builder;

fn main() -> Result<(), Box<dyn Error>> {
    let network = match std::env::var("LDK_NETWORK")?.as_str() {
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        "bitcoin" => Network::Bitcoin,
        _ => return Err("Choose an explicit supported LDK_NETWORK".into()),
    };
    let directory = std::env::var("LDK_DATA_DIR")?;
    if !Path::new(&directory).is_absolute() {
        return Err("LDK_DATA_DIR must be absolute".into());
    }
    let listen = std::env::var("LDK_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:9735".to_owned());
    let mut builder = Builder::new();
    builder.set_network(network);
    builder.set_storage_dir_path(directory);
    builder.set_listening_addresses(vec![listen.parse()?])?;
    builder.set_node_alias("Chicory primary".to_owned())?;
    builder.set_chain_source_bitcoind_rpc(
        std::env::var("LDK_RPC_HOST")?,
        std::env::var("LDK_RPC_PORT")?.parse()?,
        std::env::var("LDK_RPC_USER")?,
        std::env::var("LDK_RPC_PASSWORD")?,
    );
    builder.set_chicory_service(JitServiceConfig {
        enabled: true,
        relay_enabled: true,
        allow_confirmed_v2: true,
        allow_splice_jit: true,
        reuse_funding_key_on_splice: true,
        inbound_splice_minimum_depth: 6,
        flat_fee_sat: 100,
        fee_ppm: 1000,
        max_client_funding_sats: 500_000,
        max_total_fronted_sats: 2_000_000,
        offline_receive: OfflineReceiveConfig {
            enabled: std::env::var("LDK_ENABLE_OFFLINE").as_deref() == Ok("1"),
            max_slots: 16,
            max_budget_msat: 100_000_000,
            max_epoch_blocks: 2016,
            fee_base_msat: 0,
            fee_ppm: 0,
        },
        ..JitServiceConfig::default()
    })?;
    let node = builder.build()?;
    node.start()?;
    println!("Lightning node id: {}", node.node_id());
    println!("Native wallet funding address: {}", node.onchain_payment().new_address()?);
    println!("Commands: sync, events, quit");
    for line in io::stdin().lock().lines() {
        match line?.trim() {
            "sync" => {
                node.sync_wallets()?;
                let balance = node.list_balances();
                println!("Spendable on-chain satoshis: {}", balance.spendable_onchain_balance_sats);
            },
            "events" => {
                while let Some(event) = node.next_event() {
                    // Handle or record events before acknowledging them in a real host.
                    drop(event);
                    node.event_handled()?;
                }
            },
            "quit" => break,
            _ => {},
        }
    }
    node.stop()?;
    Ok(())
}
```

The capital and fee numbers above are explicit examples. JIT funding spends the
native wallet. The lifetime allocation ceiling is charged before funding and
retained conservatively across failures and restarts; it is not a daily limit.
Mining fees and the wallet's required reserves are additional. The provider does
not fund an offline reservation merely because a phone requested one.
The durable funding lease coordinates JIT-owned attempts only. A host that also
calls manual funding APIs must coordinate those operations separately. Offline
custody has non-evicting lifetime limits of 128 home identities globally and
4,096 archived voucher hashes or burned epoch identifiers per home. The opaque
backup store admits 1,024 peers. Exhaustion refuses new admissions; restarting
is not a way to clear persisted custody or safe replay protection.

`relay_enabled` handles sealed direct-funding protocol messages, independently of
the optional Iroh network relay. Confirmed v2 acceptance and stable funding keys
are separate policies needed for the installed phone's direct-funding paths.
Stable funding-key behavior is selected when a channel is created; changing the
flag does not retrofit an existing channel. Peer-contributed splices require six
confirmations here, including when the original home was locally funded with
zero confirmations. Do not reduce that policy to imitate the original channel's
zero-confirmation status.

An Electrum host can instead call
`builder.set_chain_source_electrum("tcp://host:port".to_owned(), None)` or use
`ssl://host:port`. Use a backend for the selected network. The funded reference
tests use Core because it tracks the mempool minimum for native inbound anchor
commitment admission. The installed phone proposes a fixed 253 sat/kw commitment
fee on fresh channels, including direct funding. Electrum and Esplora derive the
native minimum from a long-term block-target estimate, which can exceed 253 even
when the relay minimum is lower. A read-only query of the local test Electrum
server returned 0.00002006 BTC/kvB for 1008 blocks, which becomes a 502 sat/kw
minimum and rejects that phone open. The earlier funded Electrum attempt also
failed this check. Raising only the funding transaction fee does not change the
commitment fee.

The fixed commitment-fee mismatch is tracked in [Beignet issue 1873](https://github.com/coreyphillips/beignet/issues/1873).

This is a conditional limitation, not a guarantee supplied by choosing Core:
Core also rejects 253 sat/kw if its mempool minimum rises above that value. Keep
the native safety check. A native-funded JIT home uses the primary's commitment
fee, and a subsequent incoming splice preserves it, so those paths are not
blocked by the phone's fresh-open fee mismatch. Complete installed-phone
compatibility with an Electrum or Esplora primary has not been qualified. Core
conflict proofs also require its transaction index for arbitrary confirmed
transaction lookup; unavailable proof causes a refusal. Esplora and Electrum
have separate verified proof paths.

## Fund, connect, and select the primary

1. Start the node with a private persistent storage directory. Record the printed
   public Lightning id. Keep its seed and full persisted state together.
2. Fund its printed on-chain address on the selected network, then synchronize
   until the wallet reports spendable funds. The provider needs funding headroom
   and channel reserves before it can open or enlarge a phone's home channel.
3. Give the native node suitable Lightning connectivity and liquidity. Standard
   `Node::open_channel` and `Node::connect` remain available. Merely funding the
   on-chain wallet does not create a route from outside payers to this primary.
4. Configure Chicory for the same network and a reachable primary URI of the form
   `LIGHTNING_PUBLIC_KEY@HOST:PORT`. The host must be reachable from the phone;
   phone loopback addresses refer to the phone itself. The native process must
   own the Lightning public key in the URI. The phone performs its own protocol
   negotiation and pairing.
5. Exercise fixed-amount receive and outgoing payment with disposable funds
   before relying on that pairing. JIT fees reduce the amount credited to the
   home; use the compatibility record for the current Activity display caveat.

Offline receiving is a separate opt-in via `LDK_ENABLE_OFFLINE=1`. The installed
phone needs an existing compatible home and sufficient provider outbound balance
for its voucher reservation and headroom. Add local liquidity through the normal
`Node::splice_in` API when needed. The phone must complete its signed reservation
while online before an offline invoice is usable. Keep the primary running and
connected to the Lightning network while the phone is offline. Disabling new
offline admissions later does not erase existing settlement obligations.
Closing admission to an unpaid concurrent-v2 reservation leaves it in DRAINING.
The reserved voucher still blocks splicing and cooperative close on that home.
Clearing unpaid custody can require a native force-close and the actual voucher
timeout transaction reaching six confirmations; it is not an immediate return
to an ordinary usable home. The funded unpaid-lifecycle test covers this path.

The small console host above is for local operation. A long-running application
should process its event queue continuously, record application outcomes before
`event_handled`, expose authenticated administration, and stop the node on orderly
shutdown. Do not log secret-bearing payment payloads or offline receipts. Preserve
the full store, channel monitors, native seed, and journals across restart; the
phone's encrypted peer backup is not a replacement for the provider's own state.

## Optional Iroh byte transport

Keep the native listener on loopback and run the independent
[Iroh bridge](../tools/chicory-iroh/README.md) against that port. Its ready JSON
provides `LIGHTNING_PUBLIC_KEY@iroh:ENDPOINT_ID` and any configured relay URL.
The endpoint's separate `0600` identity file must persist to retain its address.
LDK still terminates BOLT8 and owns every channel and Lightning key.

Direct local testing supplies explicit socket addresses outside the URI. For
remote reachability, choose explicit relay/discovery options as documented by
the bridge. The direct transport tests do not establish public-relay or native
iOS Iroh interoperability. Use the current verification record for any additional
installed-phone evidence rather than assuming transport success proves payments.

The installed portable runtime has a separate reconnect-watchdog limitation.
Eight seconds after a primary connection, a temporary FFOR setup hold can be
mistaken for failed reestablishment and cause a forced reconnect, even after
successful payments. Direct Iroh baseline wallet checks passed, but the first
offline test hit this watchdog. A qualification fixture can wait for the initial
watchdog to finish while the restored channel is stable and usable before
starting offline setup. This scheduling workaround leaves the installed engine
unchanged and is not a production fix. See the bridge documentation for the
owning source and the measured scope, and
[Beignet issue 1872](https://github.com/coreyphillips/beignet/issues/1872) for the
integration report.
