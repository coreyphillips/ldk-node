# Local lightning 0.2.7 patch

This directory contains the published `lightning` 0.2.7 crate source, pinned to
the crates.io package checksum
`982ffb82e8362ea95e03a5de8a6004bceb7a577fc1f07d5b02cfc3fc7c930a90`.
Upstream repository: https://github.com/lightningdevkit/rust-lightning/.
The original MIT or Apache-2.0 licensing and source notices remain in place.

Local changes add `ChannelHandshakeConfig::require_zero_conf`, defaulting to
false. Explicit outbound requests require private channels, local trust in our
own funding, and peer support for both zero-conf and SCID aliases. Both required
bits are stored in the native channel type. A peer must accept with zero depth;
remote errors cannot downgrade this policy. Inbound funding trust, commitment
signatures, and monitor persistence use the existing native implementation.
The option applies only to v1 single-funded channels. Outbound v2 rejects it
until a separate policy handles trust in counterparty funding contributions.

Tests cover every combination of the five policy inputs, the encoded channel
type and depth validation, refusal to downgrade after a remote error, and real
two-node unconfirmed payments before and after persisted restart. Run from the workspace root after its
Cargo patch is configured:

```sh
cargo test -p lightning@0.2.7 --lib explicit_zero_conf
```

`UserConfig::accept_inbound_channels_v2` defaults to false. Enabling it advertises
`dual_fund` and admits the existing zero-contribution inbound v2 acceptor.
Counterparty funding requires confirmations, even if the peer is trusted for
v1 zero-conf channels. A trusted zero-conf acceptance call returns an API error
without consuming the pending v2 request. The normal acceptance API remains
available. Native outbound v2 initiation and asynchronous v2 signers remain
unsupported. Channel limits, signatures, transaction validation and durable
monitor updates remain in the native engine.

`UserConfig::minimum_inbound_splice_depth` defaults to None. A configured floor
is read from the current manager configuration when each remote splice arrives,
including for channels restored from storage. Every remote candidate, including
negative net contributions, retains the maximum of this floor, the prior
effective channel depth and any requested lock depth. A configured zero is
clamped to one. The resulting candidate override uses the existing serialized
field and survives restart without the global policy present. This prevents
trust in an initial self-funded zero-conf channel from activating a remotely
constructed splice before it confirms.

The Beignet optional `lock_depth` field is a big-endian u16 at odd TLV 65537 in
`splice_init` and `splice_ack`. Incoming requests accept depths one through six
and echo the requested value exactly. A stronger local floor remains enforced.
Native outbound initiation does not request this extension. Wire tests cover
canonical known bytes and malformed lengths, truncation and duplicates.
Runtime regressions cover invalid bounds, a negative splice contribution,
reloading an existing zero-conf channel under a new policy, peer early lock,
pending-candidate restart, and activation only at the configured sixth block.

```sh
cargo test -p lightning@0.2.7 --lib splice_
cargo test -p lightning@0.2.7 --lib confirmed_inbound_v2
```

`ChannelHandshakeConfig::reuse_funding_key_on_splice` is a creation-only,
private-channel compatibility policy, defaulting to false. Incoming public
channels retain ordinary rotating keys. Explicit outbound public requests with
this flag are rejected. The software ECDSA signer explicitly declares support;
other signers must opt in and implement matching key derivation before they can
create or restore a channel in this mode. Every funding-signature path derives
its key from the persisted channel parameters. Actual splice parent transaction
ids remain intact. A required even TLV marker appears only for enabled channels,
so older readers reject them while default serialized bytes remain unchanged.
Tests cover admission, legacy-byte compatibility, restart under a changed global
configuration, two successive splices initiated from opposite sides, payments,
and valid force-close signatures from either side after the second splice.

`UserConfig::intercept_liquidity_shortfalls`, defaulting to false, allows native
interception of an otherwise-valid forward on a real channel when adding local
liquidity can repair its failure. The classifier reruns the existing capacity
calculation with only local balance lifted, preserving remote fee, dust,
minimum, in-flight and count limits. Disconnected, shutting-down, quiescent and
already-splicing channels are excluded, as are fee-only shortages. Pending
intercepts retain their original upstream identity, onion and native CLTV
expiry. A bounded 1024-entry ceiling applies before application authorization.
Applications must authorize a payment separately before committing funds.

```sh
cargo test -p lightning@0.2.7 --lib funding_key_reuse
cargo test -p lightning@0.2.7 --lib liquidity_shortfall
```

## Confirmed splice input conflict rollback

The native rollback API accepts only the authenticated channel peer's completed
quiescence session and its exact fully signed, unconfirmed candidate. A separately
verified conflict must spend the selected external input, must not spend the
shared funding input anywhere, and must have at least six confirmations at the
current chain tip. The local integration serializes final admission with paired
manager and monitor chain application. Retirement is applied immediately to the
monitor and its response is released only after persistence. Incremental monitor
update replay verifies the saved evidence bindings without requiring an older
snapshot's chain tip to equal the proof tip.

At most 16 retired candidates are kept per channel. Required serialization fields
retain each signed alternative funding scope, commitment state, receipt identity,
preimages and chain watches across restart. Ordinary payment operation resumes
on the original funding. Exact request replay is bound to a fresh authenticated
peer-owned pause; an older response cannot release a newer pause.

A deeper reorganization that confirms a retired candidate makes the monitor
terminal and preserves the latest original branch for a further reorganization.
A stale manager must close the channel again on startup even when its counters
match and a previous close event was consumed before the manager was saved.
The monitor never broadcasts an archived holder commitment after later normal
commitments have revoked it. It retains the peer revocation secrets and can
produce a valid justice spend if the peer broadcasts its revoked branch. This
protocol uses six-confirmation finality; retaining an archive does not make a
revoked holder commitment safe to broadcast. If both parties have revoked the
archived state, the local node cannot force the peer to publish a transaction
that enables justice recovery. Full balance recovery is therefore not guaranteed
when a reorganization invalidates the accepted six-confirmation conflict proof.
This is an explicit protocol finality assumption, not a claim of protection
against arbitrary deep reorganizations.

Native regressions exercise actual signed alternative commitments, a postrollback
payment, justice signatures, monitor replay over a stale-chain snapshot, and
archive restoration. Recovery preserves pending ordinary HTLC identities. Absent outputs fail only after
the retired funding reaches six confirmations, including after restart. Invalid
recovery metadata is rejected. These native tests do not establish full wallet
feature parity or replace installed-wallet interoperability qualification.

```sh
cargo test -p lightning@0.2.7 --lib native_splice_conflict
cargo test -p lightning@0.2.7 --lib test_retired_splice_monitor_archive
```

## Private channel routing updates

Unicast routing updates set `dont_forward` until both peers have exchanged
announcement signatures. This includes permanently private channels and the
early state of channels intended for public announcement. Broadcast updates
remain forwardable. A transition to public scope advances the signed timestamp
so two different payloads do not share a timestamp for the same channel.

The existing node signer authenticates the flag with the rest of the update.
No new cryptographic operation, unsafe block, parser or persisted field is
introduced. An untrusted peer still must pass the existing chain, channel and
signature checks. This follows the
[BOLT 7 channel-update requirements](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message)
and allows a receiving wallet to hold an early private policy until its own
chain view assigns the channel SCID.

The regression checks private initial and reconnect updates, early and announced
public updates, their signatures, and increasing timestamps across scope changes.

```sh
cargo test -p lightning --lib test_channel_update_forwarding_scope
```

## Explicit trusted-client splice funding

`splice_channel_with_trusted_own_funding` permits one locally initiated positive
splice-in to lock without confirmation. The caller must own all contributed
inputs and explicitly trust the peer not to spend the previous shared funding
output in conflict with the splice. Initial splice signatures do not revoke the
previous commitment, and normal promotion does not retain the old monitor scope
for unconfirmed conflict recovery. This is a counterparty trust decision with
potential loss, not a safety consequence of funding the new inputs ourselves.

The native Chicory provider uses this API only for exact peers listed in
`trusted_splice_peer_pubkeys`, which defaults to empty. Pairing grants no such
permission. Ordinary splices, incoming splices and the third-party direct-funding
depth API retain their existing confirmation policy. The peer cannot request a
depth or contribute funding to the fast candidate. Completed interactive input
ownership is checked before commitment signing, including hidden peer inputs
whose declared net contribution is zero.

The authorization is specific to the candidate and persists across restart.
Even TLVs in splice instructions (14), pending funding (10), funding scopes (18)
and the active channel (74) cause older readers to fail closed when present.
The next ordinary splice does not inherit the candidate's zero-depth override.
No new cryptographic operation or unsafe code is introduced. The existing
[BOLT 2 splice lock exchange](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-splice_locked-message)
permits locally chosen acceptable depth; both peers still must lock the same
fully signed funding transaction before channel promotion.

Regressions cover exact-peer opt-in, config restart, candidate restart, ordinary
confirmation policy, declared contributions, requested depth, and hidden peer
inputs rejected before commitment signatures.

```sh
cargo test -p lightning --lib test_trusted_own_splice
cargo test --lib --features chicory trusted_splice_policy
cargo test --manifest-path tools/ldk-node-daemon/Cargo.toml trusted_splice
```

## Removed private offline-receive extension

The Beignet FFOR implementation, custom feature negotiation, wire messages,
signing hooks, voucher accounting and custody persistence have been removed.
Ordinary monitor snapshots remain readable. Snapshots containing the former
required custody journal or chain-proof TLVs fail with `UnknownRequiredFeature`;
they are never loaded with that custody silently discarded. Existing experimental
custody must be resolved with the prior implementation before migrating its store.

```sh
cargo test -p lightning@0.2.7 --lib removed_ffor
```
