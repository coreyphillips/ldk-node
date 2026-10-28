# Beignet v3 direct funding (`bgnq`)

A combined Bitcoin URI can include a signed `bgnq` request alongside its ordinary
Bitcoin address and Lightning invoice. A compatible payer contributes one confirmed
onchain coin directly to the receiver's channel funding transaction. The receiving
phone negotiates a new v2 channel or a splice with its configured primary. The
requested amount becomes channel balance; the payer also pays the agreed miner fee.

This is distinct from the primary advancing its own liquidity for a Lightning
payment. The primary must run the compatible native implementation with confirmed
v2 funding, splicing and Beignet relay enabled. The Umbrel daemon enables these with
its Chicory service. A new receiving phone does not need an existing channel.

## Application integration

`create_direct_funding_request(amount_sats, expiry_secs)` returns the signed
base64url request and its receipt hash. Amounts are optional; when present they must
be at least 5,000 sats. Expiration is between one second and one hour. The configured
primary must be connected and have a known address. Applications put the request
in the BIP21 query, and keep the normal address and invoice for other wallets.

Before presenting a request for payment, call `decode_direct_funding_request` to
verify the signature, network, amount and expiration. `prepare_direct_funding`
also establishes transport without reserving or spending a coin.
`send_direct_funding(request, amount_sats, max_fee_sats)` requires an explicit
absolute fee ceiling. It selects a single confirmed P2WPKH or P2TR coin which can
cover the amount, fee ceiling and change. It never silently falls back to another
payment method. Chain evidence is supported with Bitcoin Core RPC, Electrum and
Esplora; REST-only Bitcoin Core mode refuses the operation.

Use `list_direct_funding_payments` for durable activity and recovery. A
`SignedPending` payment may already have released a spendable witness. Keep
tracking it even after transport loss, expiration or application restart. Retrying
the same request recovers the original attempt; it cannot select another coin or
change its amount. A `Failed` record can represent a confirmed conflicting spend
after signing, so it is not permission to pay the combined invoice again.

Keep completed outgoing activity in the application's own activity store. The
sender retains at most 512 recovery records and prunes expired terminal records
after 30 days, or oldest expired terminal records when admitting a new payment
at capacity. Pending signed records and unexpired requests are never evicted.
Completed incoming activity is archived without its request secrets.

Call `invalidate_direct_funding_request` when another option in a combined invoice
settles, or when the user explicitly replaces the request. Merely leaving a receive
screen should not invalidate an invoice already shared. An active attempt returns
`Busy` and remains recoverable. Revocation cannot make independently shared BIP21
payment methods atomic: applications must display and track an already committed
funding attempt even if another payment arrives concurrently.

## Trust boundaries and recovery

The payer, receiver, primary relay and network can be malicious or unavailable.
The configured chain backend and local durable wallet storage are trusted for chain
evidence and crash recovery, respectively. No relay assertion substitutes for a
signature or proof of coin ownership. The receiver authenticates the signed request,
confirmed unspent coin, request-bound ownership proof and final witness. The payer
verifies the exact funding/change outputs, shared input, receiver attestations,
amount, fee ceiling and signature before releasing a witness.

Request identities, ephemeral keys, selected coins, exact transactions and signed
obligations are persisted before their associated messages can commit funds.
Reserved payer coins are excluded from ordinary spending and signing paths. A
missing receipt does not release the coin. Confirmed conflicting spends are
handled using chain evidence. Receipts are sent only after the negotiated witness
and transaction are observed on chain or in the mempool. Pending native funding
state and saved witnesses are reconciled after restart. Completed receive history
survives request expiration and later splices on the same channel.

Frames use Beignet's v3 encoding, secp256k1 ECDH, HKDF-SHA256 with request-specific
salt and separate directional labels, and RFC 8439 ChaCha20-Poly1305. Every send
uses a fresh random 96-bit nonce, including retransmission. Request identity and
message subtype are authenticated associated data. Identity signatures follow
Beignet's Bitcoin signed-message format. Signing and ECDH use libsecp256k1; AEAD
uses RustCrypto. Ephemeral lane keys are cleared on drop. The storage journal
contains secret material and requires the same protection as the node wallet.
Transport queues, message size, rates, request count and session count are bounded.
The endpoint module forbids Rust `unsafe` code.

## Verification

Protocol fixtures come from Beignet's envelope, messages and frame implementation.
Codec property tests exercise arbitrary bytes and signed request round trips.
Sender tests cover amount and fee tampering, real wallet witness validation,
reservation persistence, exact witness replay, changed transactions, lost receipts
and failures on either side of the durable commitment boundary. Receiver tests
cover revoked requests, historical activity, restart recovery, chain witness
binding, journal corruption and continuation through the originally selected
primary. Vendored LDK tests cover real external-input v2 funding, splice depth
persistence and asynchronous monitor gating.

Run `cargo test --lib --features chicory direct_funding` and
`cargo test -p bdk-wallet-aggregate --lib`. The funded test requires a disposable
Bitcoin Core regtest RPC endpoint and refuses any other network:

```sh
cargo build --example chicory-primary --features chicory
python3 scripts/direct-funding-regtest.py --rpc-url rpc://user:password@127.0.0.1:18443
```

It opens a 100,000-sat channel, funds a 40,000-sat splice, checks the exact resulting
140,000-sat channel and zero onchain fallback, then retries and restarts both
endpoints to check that only two payments remain. Each run keeps disposable logs
and an evidence file in a temporary directory. It does not qualify mainnet funds,
hardware failure, every partition schedule, or every external wallet version.

The isolated `fuzz/direct-funding` crate exercises the production parsers and AEAD
opening boundary without a node or network. Run `cargo fuzz run direct_funding_wire`
from that directory with cargo-fuzz and a supported nightly toolchain. For a smoke
run without sanitizers, `cargo run --manifest-path fuzz/direct-funding/Cargo.toml
--bin direct_funding_wire -- -runs=10000` also executes the target. Instrumented
fuzzing and property tests complement targeted tests; they do not demonstrate
complete line or branch coverage.
