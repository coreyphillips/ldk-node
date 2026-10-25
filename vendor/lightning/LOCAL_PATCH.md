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

The experimental concurrent FFOR settler uses native voucher HTLC identities,
R/S-oriented commitment snapshots and a monitor-owned custody journal. Setup
requires an idle NORMAL anchor channel without a BOLT STFU session, plus native
reserve, dust, count and in-flight checks. Activation begins quiescence only
after the vouchers are irrevocably committed. The entire voucher batch remains unassigned in the holding
cell until its secret custody update is durable. A failed batch rolls back
without consuming HTLC ids. Activation binds the exact two irrevocable,
untrimmed native commitments and remains gated on monitor persistence.

Required fields retain the journal in both the channel and monitor, rejecting
older readers when custody exists. Restored journals bind to the authenticated
counterparty, channel and funding outpoint. Epoch and payment-hash archives do
not evict old identities. A slot's upstream claim binding cannot change after
SETTLING, and its completion token must be covered by an actually persisted
native monitor update. Metadata-only descendants preserve earlier completion
tokens while preventing claim rollback. Force-close retains the journal and
allows completion of previously bound claims without admitting new claims.

While a concurrent reserved book is live, native commitment checks preserve
its untrimmed voucher subset during ordinary payments. Fees, splices and
cooperative close remain blocked. Reserved vouchers cannot be failed after
activation, including while draining. Fulfillment and two-view removal require
native monitor evidence for the exact voucher identity. Onchain custody is
retained independently of the manager; commitment counters must never be
invented to stand in for chain resolution evidence.

The monitor records authenticated chain outcomes for the exact funding outpoint,
voucher HTLC and payment hash only after six confirmations. It retains these
proofs across restart and a lost callback until the resulting custody journal
is durable. Pending SETTLING upstream obligations survive chain retirement;
new delegated claims cannot use a resolved voucher. Native tests broadcast
real signed commitment and timeout or fulfillment transactions, restart below
the threshold, withhold monitor persistence, replay the proof, and restart after
journal completion. These are native tests, separate from installed-phone
interoperability qualification.

An FFOR journal containing a chain removal requires a complete monitor snapshot.
The incremental persister preserves the original update ID and reports completion
only after that snapshot is durable. The journal does not authenticate its own
chain evidence: replay still requires the monitor's independently derived proof.
This matters when the final claim matures between periodic chain snapshots.
Custom incremental persisters must honor
`ChannelMonitorUpdate::requires_full_monitor_persistence`. Native timeout and
fulfillment regressions deliberately retain a pre-threshold base, delay the async
snapshot write, and reload through the actual incremental persister after both
the proof journal and its payment-completion update.

Ordinary voucher redemption also waits for native commitment finalization.
Receiving `update_fulfill_htlc` alone cannot mark a voucher redeemed. Bounded
current-epoch proof survives the final revocation and the crash window before
the corresponding FFOR journal update. Tests cover withheld commitment and
revocation persistence and restart with new FFOR admission disabled.

`channel_reestablish` carries Beignet's optional odd TLV 55001 as exactly 67
bytes. The manager coordinates signed state reconciliation and owed activation
acknowledgments before releasing ordinary channel replay. The bounded wire,
transcript and signer tests include Beignet's published local fixture vectors.
Runtime support remains experimental and disabled by default. The local Node
integration must not advertise protocol readiness until native settlement,
restart, reconnect and close qualification has completed.

```sh
cargo test -p lightning@0.2.7 --lib ffor
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
archive restoration. Recovery preserves pending ordinary HTLC identities and
FFOR custody created on the surviving funding. Absent outputs fail only after
the retired funding reaches six confirmations, including after restart. Invalid
recovery metadata is rejected. These native tests do not establish full wallet
feature parity or replace installed-wallet interoperability qualification.

```sh
cargo test -p lightning@0.2.7 --lib native_splice_conflict
cargo test -p lightning@0.2.7 --lib test_retired_splice_monitor_archive
```
