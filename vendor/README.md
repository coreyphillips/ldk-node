# Pinned native protocol dependencies

These directories contain local copies of the published 0.2.7 Rust crates.
The root workspace patches crates.io to these paths and tests the modifications
as workspace packages. Nothing here is published by this branch.

| Crate | Original crates.io archive SHA256 |
| --- | --- |
| lightning 0.2.7 | `982ffb82e8362ea95e03a5de8a6004bceb7a577fc1f07d5b02cfc3fc7c930a90` |
| lightning-liquidity 0.2.7 | `75947be75873138097adb72c080a853ad576a295ac63f73d8fbeb07543c136b1` |

Original license files and copyright notices are retained. The checksums above
identify the original archives, not these modified source trees.

The Lightning patch adds explicit, opt-in zero-conf negotiation for an outgoing
v1 channel. It requires a private channel, directional trust in our own funding,
and the peer's zero-conf and SCID alias features. It preserves the agreed channel
type in native channel state, rejects a nonzero acceptance depth, and prevents
fallback from silently removing the requested zero-conf policy. It rejects this
option for outbound v2 channels because contributed-input trust is not covered.

It also adds an explicit opt-in for confirmed, zero-contribution inbound v2
channels. The native primary uses this for a phone's initial third-party-funded
channel. Outbound v2 initiation and asynchronous v2 signing are not enabled.
Peer-initiated splices have a configurable confirmation floor, including when
the original channel was zero-conf. The candidate's required depth persists
across restart. Beignet's optional splice lock-depth TLV is validated and
echoed without reducing this local floor. See `lightning/LOCAL_PATCH.md` for
the policy boundaries and regression commands.

Private compatibility channels may opt in at creation to stable funding keys
through successive splices. Public channels retain the default rotating-key
behavior. The policy is persisted, requires explicit signer support, and uses
a required even marker so older readers refuse incompatible channel state.
Native shortfall interception is separately opt-in and preserves the upstream
HTLC and onion while the application authorizes an existing-home JIT splice.
It applies only where additional local liquidity can repair the forward.

The liquidity patch adds an ownership-aware intercepted-HTLC dispatch result.
The original API remains available. LDK Node can now fail unknown or expired
intercepts instead of leaving them pending when an LSPS client or unrelated
LSPS provider is configured alongside the Chicory service.

The Lightning patch also contains an opt-in native concurrent-v2 FFOR settler.
Its signed transcripts, voucher commitments, delegated upstream claims,
reconnect metadata and chain-resolution proofs use native channel and monitor
state. Required serialized fields reject older readers when custody exists.
Monitor persistence gates every acknowledgment and claim; disabling new
admission preserves existing obligations. See `lightning/LOCAL_PATCH.md` and
the root compatibility guide for tests and current qualification limits.

The standalone fuzz workspace repeats these path patches. Applications which
consume this branch as a dependency must also copy its `[patch.crates-io]`
configuration into their top-level Cargo manifest: Cargo does not inherit
dependency patch sections.
