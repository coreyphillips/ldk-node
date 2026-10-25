# Chicory primary compatibility

This branch adds native Beignet protocol support so LDK Node can act as a Chicory
primary on the tested paths. Funded tests cover ordinary payments, multipart JIT
receiving and existing-home JIT splicing, deposits, Bitcoin sends and drain,
confirmed direct funding, conflict rollback, peer backup recovery, and concurrent-v2
offline receiving. The native iOS wallet, normal iOS application screens, and direct and forced
public-relay Iroh transports also passed their recorded payment and offline fixtures.

This remains experimental. The recorded scenarios establish behavior for the
identified builds and transports, rather than universal equivalence or production
security. Local client compatibility fixes and the remaining limits are recorded
below. Successful pairing alone does not establish payment or recovery parity.

See [running a primary](chicory-running.md) for the public Builder configuration,
funding and pairing steps, and optional Iroh transport. The
[native iOS fixture](chicory-ios-testing.md) describes the isolated simulator
build and its scope.

The source audit used Chicory 0.7.4 with these installed dependencies:

- `@beignet/portable-engine` commit
  `67bc9cf0ba3e55fa1e1d7ad73e360bb04321a62c`, based on Beignet 0.32.1
  (`daed636187e42bfbd156e5f5b74fda9c7a6379cd`).
- `@beignet/wallet-core` commit
  `cc544e6b712f4ef9042dd24e9a5b64def2f9f53b`.
- LDK Node's `lightning` dependency at 0.2.7.

The branch includes local `lightning` and `lightning-liquidity` 0.2.7 source
patches documented in `vendor/README.md`. The first adds opt-in outgoing v1
zero-conf negotiation with explicit funding trust, private-channel and peer
feature checks, confirmed inbound splice policy, stable funding keys for private
compatibility channels, and an experimental confirmed v2 acceptor. The second
lets the event dispatcher distinguish an owned
liquidity intercept from an unknown one. The native JIT path depends on these
patches. A consuming application's top-level manifest must retain the path
patches; Cargo does not inherit a dependency's patch section.

The installed application is the contract. Some older descriptions in
`FFOR-VALIDATION.md` describe automatic offline requests and provider-funded
reservation channels. Current Chicory makes offline receiving an explicit
choice and requires an existing eligible channel.

## Architecture and trust boundaries

Chicory holds its own keys, channel state, invoices, and transaction history in
the phone's portable Beignet engine. A primary is a Lightning peer reached over
BOLT 8. Paths such as `/jit/quote`, `/receive/invoice`, and
`/channel/splice-out` are calls inside that local engine. They are not HTTP
endpoints that the primary must implement.

The usual pairing string is `<compressed-node-public-key>@<host>:<port>`.
Clearnet and Tor supply byte transports. Iroh is an additional optional
transport carrying the same authenticated Lightning protocol. A successful
standard TCP connection is useful but does not qualify Iroh compatibility.

The native service is enabled through `Builder::set_chicory_service` and
`chicory::JitServiceConfig`. Its default is disabled. The current implementation
accepts fixed-amount JIT requests with at most 16 parts per payment, uses an existing
channel when it has sufficient capacity, or opens a new private channel for a
peer without one. An additional opt-in enables genuine capacity-shortfall
interception and JIT splicing of the existing home. This requires confirmed
wallet inputs and forwards only after the exact replacement funding becomes
ready. Registration, funding allocation budgets, and held-payment state
are persisted. The default global limit is 16 held HTLCs. All parts share the
first part's 60-second hold deadline, bounded by authorization expiry. A group
charges the flat fee once, with aggregate skim rounding or per-part hop-fee
rounding matching Beignet. Interrupted gathering and funding groups fail
conservatively after restart, consume their authorization, and retain any
already charged funding allocation. Restart does not resume an interrupted
payment or initiate another channel for it. Unused registration replay remains
idempotent across restart.
The installed Beignet client authorizes before creating its invoice and omits
the payment hash. Such an authorization is a one-use intercept SCID capability:
the first valid matching HTLC atomically binds its hash in durable storage.
Further parts must match that hash and remain inside the authorization cap.
The group consumes its request before funding or forwarding. A supplied hash
must match.
An independent durable funding lease serializes JIT-owned wallet funding attempts.
Manual funding through Node administration APIs must use
`Node::with_chicory_wallet_operation` to coordinate with ongoing JIT funding.
The native dashboard daemon wraps its channel opens, splices, and Bitcoin sends
with this guard. Unwrapped host calls remain outside the funding lease.
Failing held HTLCs, authorization expiry or restarting the primary does not
release a still-pending native funding operation. Late funding results must
match the recorded channel and outpoint before the lease can clear. The relay
has a separate opt-in; initial direct funding also requires the v2 acceptor.
Existing-home direct funding requires private channels created with the stable
funding-key policy. Public channels continue using ordinary rotating keys.

Peer-storage writes have a per-peer burst allowance of eight, refilling one
write per second, and a global burst allowance of 64, refilling 16 writes per
second. Failed storage attempts consume credit. Excess writes preserve the
previous durable blob and return a bounded warning. Credits survive reconnect
and reset on provider restart; retrieval does not consume write credit.
The backup store admits at most 1,024 peer identities. Native offline custody
retains at most 128 home identities globally and 4,096 archived voucher hashes
or burned epoch identifiers per home. These records are not evicted to admit
new work. Exhaustion refuses new admission; restarting does not reset the
persisted custody history.

Threat model:

- An authenticated peer can still be malicious. It can send malformed frames,
  replay authorizations, change request parameters under a reused identifier,
  exhaust storage, or request funding it will never use. Authentication does
  not authorize an unlimited funding budget.
- A payer can split a payment, withhold parts, send an incorrect total, offer an
  insufficient CLTV, disconnect, or retry. Every intercepted HTLC must resolve
  once without funding or forwarding beyond the authorized amount.
- Network partitions, stale chain observations, process crashes, and failed
  durable writes can occur between every protocol step. Acknowledgments must
  not promise state that cannot survive the required restart boundary.
- Zero-conf trust is directional. Authorizing the primary to fund a client is
  not permission to accept unconfirmed channels funded by that client.
- Peer backups are opaque, peer-scoped data. The provider must not decrypt them,
  return them to another identity, silently truncate them, or claim persistence
  when its storage write failed.
- Third-party funding inputs can be double spent. FFOR participants can present
  stale or conflicting voucher histories. These require their specified channel
  and chain verification rules, not application-level balance adjustments.

Keep ordinary transport encryption, signing, and channel accounting in LDK.
Do not introduce a second wallet or make a Beignet process the hidden channel
owner. Neither would establish native LDK Node parity. This audit does not
establish a production security audit of the FFOR port.

## Native port prerequisite matrix

Source names below are relative to the named checkout. Installed phone sources
are under `chicory/node_modules/@beignet/portable-engine/portable/` and
`chicory/node_modules/@beignet/wallet-core/src/`.

| Capability | Chicory and Beignet contract | Native prerequisite and current qualification boundary |
| --- | --- | --- |
| Pair and reconnect | `primary-uri.cjs:4`, `runtime.ts:421`; BOLT 8 to the exact configured node key. Setup becomes ready after a connected peer. | Existing Lightning transport is the base. Verify against the unchanged phone engine, including full process restart and channel reestablishment. Pairing alone is insufficient. |
| Ordinary Lightning | BOLT11, route hints, channel readiness, both payment directions, MPP, and forwarding through the primary. | Existing LDK behavior must be tested with Beignet commitments and invoice semantics. A direct payment to the primary does not test forwarding. |
| Custom framing | Beignet `src/lightning/message/custom.ts`: wire type `44069`, followed by big-endian `u16 version`, `u16 subtype`, and payload. Version is `1`; application payload maximum is 65,529 bytes. Unknown versions and subtypes are ignored. | Native custom message handling must coexist with existing liquidity protocols. Malformed or oversized input must not panic, allocate without bounds, or disconnect an otherwise valid peer unnecessarily. |
| JIT quote and authorization | `wallet-core/src/index.js:2392` and `:2600`; subtypes `4/5` quote and `1/2` authorization/ack. Phone requests 10,000 sats headroom and explicitly requests skim fees using the quote's ceilings. | Implemented with installed-phone quote and authorization checks. A quote is read-only. Authorization binds the peer, request, hash, amount, fee mode, expiry, and intercept SCID. A protocol reply alone does not demonstrate delivery. |
| JIT funding and forwarding | Beignet `src/lightning/liquidity/jit-receive.ts`; hold incoming parts, provision an outbound zero-conf channel or enlarge the existing home, deduct the agreed fee, forward, and resolve the upstream HTLCs. | Funded single-part and two-part checks passed for new channels and existing-home JIT splices, with exact skim fees and one home. Restart and refusal behavior are bounded as described above; arbitrary late multipart patterns remain unqualified. |
| Deposit channelization | `portable/channelize.cjs:43` and `lfbw.cjs:476`; confirmed coins at or above 25,000 sats enter the home channel. Initial phone-funded opens use `buyInbound: false` in the installed runtime. | LDK Node already has splice APIs and permits inbound splices. Cross-engine wire and commitment compatibility still requires funded tests. Current phone deposit setup does not require a liquidity-ad purchase. |
| Bitcoin sends and send-max | `runtime.ts:1236` calls `spliceOut`. `portable/drain.cjs` coordinates an explicit full-wallet drain. Optional zero-reserve terms affect how much remains spendable. | Verify splice-out destinations and fees, reserve semantics, confirmed funding checks, failed broadcasts, cooperative close, and durable restart. A reverse swap is not the application's send path. |
| Direct funding | `lfbw.cjs:399` enables ordinary and unpaired splicing. Beignet custom subtypes `16` through `22` carry offers, signing requests, witnesses, receipts, and relay. | Both an existing-home 5,000-sat payment and a fresh receiver's 15,000-sat payment passed with the unchanged installed portable engine. The tests verify receipts, exact chain inputs and outputs, matching usable native funding, and a subsequent 1,000-sat Lightning spend from each channel. The existing-home path uses the opt-in stable funding-key policy. |
| Conflicted direct-funding splice | Beignet custom subtypes `64/65`, `src/lightning/message/splice-conflict.ts`; unpaired contributions wait for their configured lock depth and verified conflicts may revert to prior funding. | Implemented with authenticated chain proof, bounded workers, native monitor retirement and durable acknowledgments. The installed phone passed five/six-confirmation handling, both restarts and a subsequent payment from the restored original funding. The native archive retains recovery branches and refuses revoked holder broadcasts after deep reorgs. |
| Offline receiving | `offline-receive.ts:296`, `:450`, and `:586`; subtypes `80/81` request terms and receipts. FFOR uses optional bits `561/563`, epoch activation, voucher reservations, receipt sync, and draining. | Implemented as an opt-in native concurrent-v2 settler with exact voucher accounting, commitment transcript binding, persistence gates, delegated upstream settlement, synchronization, and chain custody. Native lifecycle tests and installed-phone receipt recovery pass, including native iOS storage and process restarts. Historical issuer and witness variants are outside the installed phone contract. |
| Peer-storage recovery | `runtime.ts:548` selects `peer-storage`. Beignet `src/lightning/message/peer-storage.ts` uses type `7` to store and type `9` to retrieve. Each contains a `u16` length and opaque bytes. Beignet pads its outgoing capsule to 65,531 bytes in `lightning-node.ts:6535`. | Stock LDK 0.2.7 rejects blobs above 1 KiB. This branch adds a channel-message wrapper that accepts bounded full-sized opaque blobs from established channel peers and returns the current durable blob to the same authenticated peer. Live restart retrieval, empty-phone recovery with the reference safety hold, and a real current-commitment recovery sweep passed. |
| Iroh | Chicory `docs/IROH.md` and `portable/primary-uri.cjs`; same Lightning key, separate endpoint identity, optional same-key onion fallback. | An independent byte bridge passed direct Iroh and forced public-relay wallet tests, including all 11 baseline/offline checks. Endpoint identity, bounded cancellation and native BOLT 8 are tested. See the later qualification records for discovery, fallback and native iOS adapter results. |

Current Chicory does not expose reverse or submarine swaps. The installed
portable README explicitly states that providers are disabled and there is no
wallet-side swap client. Implementing custom swap subtypes `48` through `55`
does not substitute for any prerequisite above.

The direct-funding first-channel path has no v1 fallback. Beignet
`src/lightning/direct-funding/receiver/engine.ts:2001` calls `openChannelV2`
with the payer's external contribution, and
`src/lightning/node/lightning-node.ts:28458` binds that dependency directly to
the v2 implementation. `src/lightning/channel/channel-manager.ts:7487`
rejects a primary that did not advertise `option_dual_fund`. The installed
phone bundle contains the same calls at
`node_modules/@beignet/portable-engine/dist/portable.cjs:146113` and the
feature rejection at `:121204`. The generic `openChannel` method has a v1
fallback, but this receiver path never calls it. Relay support plus a v1
channel with a push therefore cannot complete an unchanged phone's
direct-funding request.

FFOR has its own odd message types in addition to the custom envelope:
`55001`, `55003`, `55005`, `55023`, `55045`, `55047`, `55049`, `55051`,
`55053`, `55075`, and `55077` for the receiver/settler protocol. Witness and
issuer extensions use `55055` through `55073`. The authoritative definitions
are Beignet `src/lightning/message/types.ts` and
`docs/specs/ffor-offline-receive.md`; concurrent behavior is specified in
`docs/specs/CONCURRENT-RECEIVE.md`.

The current phone requests one fixed-amount Variant D slot on an existing home,
with admission deadline at the current height plus 144 and voucher expiry plus
1,296 (`portable/offline-receive.ts:507`). The reference provider selects
concurrent version 2 (`beignet/src/cli/ffor-receive.ts:236`), which preserves
unpaid claims after retirement. Its standard commitments continue advancing
while preserving voucher outputs. A baseline epoch requires the phone to have
zero local channel balance, so implementing baseline alone changes ordinary
funded-home behavior. Variant D does not require the unilateral fast-forward
commitments of historical variants A and B. The existing concurrent specification
has a stale draft status header; the installed engine and current reference
tests are needed to pin version 2 behavior.

Splicing uses STFU `2`, splice-init `80`, splice-ack `81`, splice-locked `77`,
start-batch `127`, and interactive transaction messages `66` through `74` in
the audited Beignet tree. Verify their semantics and feature negotiation
against LDK, not only these message numbers.

## Acceptance scenarios

These are acceptance requirements, not recorded passes. Capture exact revisions,
configuration, process identities, funding outpoints, balances, transaction IDs,
and bounded test results. Never record seeds, preimages, or private keys in the
evidence. Use disposable regtest wallets and a separate mobile test identifier.

1. **Baseline peer and forwarding:** connect the unchanged phone engine to the
   native provider, fund a channel, and complete payments both ways. Add a third
   node and complete payments through the provider. Restart each endpoint and
   repeat. Inspect unsupported feature handling and malformed custom frames.
2. **JIT quote:** with no phone channel, request a fixed-amount receive quote.
   Verify exact fee rounding, headroom, current capacity/refusal policy, and
   that quotes do not reserve funds or create intents. Test disabled service,
   insufficient funds, exceeded budget, malformed input, and stale requests.
3. **JIT delivery:** authorize an invoice, pay through a third node, and verify
   the provider creates capacity before forwarding. Confirm the exact receiver
   amount, provider fee, sender result, one home channel, and one Activity entry.
   Repeat with insufficient inbound on an existing home and verify that the home
   grows. Repeat with every supported fee mode and multipart payment pattern.
4. **JIT failure and restart:** partition after authorization, after intercept,
   during funding, and before forwarding. Kill the provider at each durable
   boundary. Retry exact and changed request IDs, send wrong hashes/totals,
   expire partial multipart payments, and deliver a funding result late.
   Verify bounded funding exposure and that every held HTLC is fulfilled or
   failed exactly once. Never report failure while delivery remains possible.
5. **Deposit and splice:** deposit 30,000 sats into a phone with a home channel,
   confirm it, and assert one larger usable home with no phantom send. Repeat
   without a home. Send to Bitcoin addresses using P2WPKH, P2TR, and P2WSH
   destinations. Verify actual chain outputs, fees, confirmation rules, and
   persistence through restart, refused broadcast, and reorg.
6. **Direct funding:** a second phone with a confirmed coin below its automatic
   channelization floor pays the recipient's unchanged unified request. Force
   the primary relay path. Test existing-home and initial-channel cases,
   unpaired sender lock depth, tampered witnesses, replay, disconnect, and a
   confirmed conflicting input spend. Assert a single correct funding spend
   and receipt, with no leaked signing material or false completion.
7. **Offline receive:** establish an eligible funded home, prepare a concurrent
   reservation, stop the phone process, and pay externally. Reopen twice and
   verify one credited receipt and no balance inflation. Exercise partial
   redemption, an unpaid voucher, expiry, unknown slots in DRAINING, ordinary
   payments using remaining capacity, provider restart, and conflicting sync.
   A disabled offline policy must refuse explicitly without reserving vouchers.
8. **Recovery storage:** send the phone's real 65,531-byte padded capsule,
   restart the provider, reconnect, and compare retrieval byte-for-byte. Test
   durable write failure, another peer requesting retrieval, rate limits, and
   oversized messages. Restore into an isolated installation using explicit
   recovery opt-in and ensure the old process cannot resume unsafe signing.
9. **Send-max and drain:** cover a primary-funded channel with and without a
   reserve waiver, a phone-funded channel, exact fee ceilings, subsequent
   receipts excluded from a frozen review, cooperative close plus loose-coin
   sweep, and restart with one complete Activity row. Later chain confirmation
   must not block fresh receives after a safely completed drain boundary.
10. **Native mobile transport:** run the passing portable scenarios with the
    isolated Chicory native test entry using Hermes, native TCP, Keychain, and
    SQLCipher. Qualify Iroh independently if offered by the provider.

## Minimal cross-engine quote smoke test

A small script can test real BOLT 8, custom framing, request correlation, and
quote decoding without building a simulator. Use the built Beignet source
package as the client. The installed portable package does not export
`BeignetNode`, so do not import that class from `@beignet/portable-engine`.

Start the native Rust provider example on regtest, obtain its Lightning URI,
and fund it if testing an accepted quote. Save the following as a temporary
`.cjs` file. Set `BEIGNET_SOURCE_DIR` to a built Beignet checkout,
`CHICORY_PRIMARY_URI` to the example's URI, and `EXPECT_JIT_ACCEPTED` to `1`
for a provisioned provider or `0` for an intentional refusal. Set
`ELECTRUM_HOST` and `ELECTRUM_PORT` to the same regtest network as the provider.

```javascript
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

async function main() {
  const source = process.env.BEIGNET_SOURCE_DIR;
  const uri = process.env.CHICORY_PRIMARY_URI;
  const expected = process.env.EXPECT_JIT_ACCEPTED;
  assert.ok(source, 'BEIGNET_SOURCE_DIR is required');
  assert.ok(expected === '0' || expected === '1', 'Set EXPECT_JIT_ACCEPTED');
  const parsed = /^(0[23][0-9a-f]{64})@([^:]+):(\d+)$/i.exec(uri || '');
  assert.ok(parsed, 'Use a regtest TCP URI for this smoke test');
  const { BeignetNode } = require(path.join(source, 'dist/cli/beignet-node.js'));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chicory-wire-smoke-'));
  let node;
  try {
    node = await BeignetNode.create({
      network: 'regtest', dataDir, allowMultipleInstances: true,
      electrumHost: process.env.ELECTRUM_HOST || '127.0.0.1',
      electrumPort: Number(process.env.ELECTRUM_PORT || 60001),
      electrumTls: false, autoBootstrap: false, autoGossipSync: false,
      logger: { debug() {}, info() {}, warn() {}, error() {} }
    });
    await node.connectPeer(parsed[1], parsed[2], Number(parsed[3]));
    const quote = await node.getJitQuote({
      lspPubkey: parsed[1], amountSats: 20000,
      targetRemainingInboundSat: 10000
    });
    assert.equal(quote.accepted, expected === '1');
    assert.equal(typeof quote.withinCeilings, 'boolean');
    for (const key of ['flatFeeSat', 'feePpm', 'feeSats', 'fundingSats']) {
      assert.ok(Number.isSafeInteger(quote[key]) && quote[key] >= 0, key);
    }
    console.log(JSON.stringify({ test: 'bolt8-jit-quote', quote }));
  } finally {
    if (node) await node.gracefulShutdown(5000);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
```

An accepted result proves only the exchange described above. It does not prove
that a payer can reach the intercept SCID, that a channel can be funded, that
skim accounting works, or that an interrupted payment is safe. The acceptance
scenarios must test those separately.

## Existing fixtures to adapt

The local native JIT fixture is `scripts/chicory-interop.cjs`:

```sh
cargo build --features chicory --example chicory-primary
BEIGNET_SOURCE_DIR=/path/to/built/beignet node scripts/chicory-interop.cjs
```

It verifies that the Docker chain is regtest before funding, creates a native
provider and two disposable Beignet clients, checks blind relay delivery and
explicit offline-service refusal, establishes a payer channel,
requests and authorizes a skim-fee invoice, restarts the provider, replays the
authorization, and pays through the provider to a receiver that initially has
no channel. Its assertions cover a 20,000-sat request with the example's
100-sat plus 1,000-ppm fee, an excessive-request refusal, the same intercept
SCID after restart, a single receiver home channel, and 19,880 sats delivered.
It also sends a 65,531-byte padded opaque backup and compares its contents after
a reconnect and another provider restart. This verifies the storage transport
and persistence, not recovery of an erased phone or cryptographic backup validity.
These are script assertions, not a claim that the run has passed.

`CHICORY_PRIMARY_BIN` selects an already built driver, including the normal-feature
`tools/chicory-primary/target/debug/chicory-primary-local` host, `CHICORY_ELECTRUM_URL`
selects the Beignet clients' chain connection, `CHICORY_PRIMARY_CHAIN_SOURCE`
selects the native provider's chain connection, and `BEIGNET_EVIDENCE_FILE`
saves public checkpoint results. The provider defaults to the local Docker
Bitcoin Core RPC service. Failed runs retain their disposable regtest directories for diagnosis.
`CHICORY_KEEP_TEST_STATE=1` also retains a successful run. This fixture uses the
built Beignet client API; the full application acceptance plan additionally
requires the installed portable client and native phone entry.

`scripts/chicory-mpp-interop.cjs` exercises two actual 10,000-sat HTLCs from
Beignet's existing multipart sender against one unchanged 20,000-sat receiver
invoice. Both parts use the same authorized intercept SCID. It restarts the
provider after authorization, proves two distinct payer HTLC ids and receiver
HTLC ids, and checks two native forwarding events. The accepted result must
open exactly one receiver channel, skim exactly 120 sats once, and deliver
19,880 sats. The measured funded run below passed. That run restarts before
the parts arrive; interrupted partial groups are covered by service tests,
not by a live mid-payment crash in this fixture.

```sh
BEIGNET_SOURCE_DIR=/path/to/built/beignet node scripts/chicory-mpp-interop.cjs
```

`scripts/chicory-portable-interop.cjs` uses the exact portable engine and
wallet-core under the Chicory checkout's installed `node_modules`, with a
native TCP/TLS socket adapter implementing the package's `SocketFactory`
interface. It does not rebuild or patch those packages. It records their SHA256
fingerprints, uses a durable disposable phone volume, and exercises wallet-core
pairing, the JIT quote and unified request, external payment, Activity and balance
checks, a portable runtime restart, and a Lightning send to the native primary.

```sh
CHICORY_SOURCE_DIR=/path/to/chicory \
BEIGNET_SOURCE_DIR=/path/to/built/beignet \
node scripts/chicory-portable-interop.cjs
```

The same primary, Electrum, Bitcoin container, timeout and evidence environment
variables apply. `CHICORY_TEST_INITIAL_DEPOSIT=1` runs a separate first-deposit
fixture: a confirmed 30,000-sat coin creates one phone-funded home, the primary
keeps it unusable at zero confirmations and across restart, then both engines
activate it at confirmation and complete a 1,000-sat spend and phone reopen.
`CHICORY_TEST_RECOVERY=1` imports the seed into a new empty phone volume after
stopping the old installation and restarting the primary. It verifies that the
stored capsule restores the exact home and balance. Beignet deliberately keeps
`restoreRecencyUnproven` after a compatible reestablish: a peer that stores the
capsule cannot prove it has returned its newest state. The restored balance
therefore remains unavailable to new HTLCs. This is the reference safety behavior,
not a missing native recovery acknowledgment. The old installation stays stopped.
`CHICORY_TEST_RECOVERY_SWEEP=1` additionally asks the disposable primary to
broadcast its current commitment, then verifies the restored phone sweeps the
matching output without signing stale channel state. Run recovery separately
from the other optional payment paths.

`CHICORY_TEST_SPLICES=1` additionally asserts automatic
channelization of a confirmed 30,000-sat deposit into the existing home, then a
2,000-sat splice-out with exact on-chain destination proof. Its deposit
regression now stops mining once the splice candidate enters the mempool,
requires the native primary to retain its previous active funding outpoint
and channel value, restarts the primary and reconnects both peers, and checks
that the candidate remains inactive. Five confirmations must still leave the
previous funding active; the sixth must promote the candidate and deliver the
deposit. This six-confirmation candidate policy isolates trust in the
primary's original zero-conf funding from trust in later peer-funded inputs.
The funded regression passed all eleven checks on 2026-10-25 UTC, including
the zero-confirmation restart and five/six-confirmation boundary below.
`CHICORY_TEST_JIT_SPLICE=1` separately tests a single 30,000-sat payment that
exceeds the existing home's inbound liquidity but remains below its original
HTLC maximum. The native primary holds that HTLC, enlarges the same home from
40,000 to 90,000 sats, and forwards 29,870 sats after the agreed 130-sat fee.
The fixture confirms the provider's previous change before requesting the
splice and verifies both engines' exact active funding and channel value.
It does not qualify late multipart arrivals during splice quiescence.

The separate `scripts/chicory-mpp-interop.cjs` fixture accepts
`CHICORY_MPP_EXISTING_HOME=1`. It first reduces a 40,000-sat home's remaining
inbound liquidity to 12,120 sats, then dispatches two actual 15,000-sat parts
through the real home alias, each with its advertised routing fee. Both parts
are therefore genuine liquidity shortfalls while staying within the original
channel policy limits. The native primary gathers both, splices once to
90,000 sats, and forwards 14,870 plus 15,000 sats. The 130-sat JIT fee is charged
once, independently of the two ordinary 1-sat routing fees. This case passed;
parts arriving after quiescence starts remain a separate failure/retry case.

`CHICORY_TEST_DIRECT_FUNDING=1` adds two direct-funding scenarios to the portable
fixture: a 5,000-sat payment into the existing home, followed by a 15,000-sat
payment opening a fresh receiver's first home. Each payer runs the exact
installed portable engine and wallet-core in a separate process, holds one
confirmed 20,000-sat coin below the 25,000-sat channelization floor, and uses
the real `quoteReceive`, `receive`, `prepareSend` and `send` APIs. The fixture
requires a `bitcoin` / `direct-funding` review with the 1,000-sat fee ceiling;
it refuses address or Lightning fallbacks. It checks the completed payer
Activity amount, persisted receipt preimage against the signed request's
hash, attested 2-of-2 funding script, exact funding output value and receiver
balance increase, and the payer coin as a transaction input. The existing
home case also requires its previous funding outpoint as an input. It does
not alter advertised features or either installed phone package. These
scenarios also require both sides to activate the same funding, followed by
a real 1,000-sat Lightning spend from each channel. All ten checks passed in
the complete run below.
`CHICORY_DF_ONLY_FRESH=1` explicitly skips the existing-home case and records
`directFundingScope: initial-channel-only`. That diagnostic scope passed the
earlier seven-check run below. Its scope must not be confused with the later
complete run. Public JSON evidence excludes
receipt preimages, witnesses, seeds and serialized payment records.

An initial rotating-key existing-home run failed before the payer released its witness because
Beignet attests the committed funding keys while the splice output uses the
newly negotiated remote key. The payer also requires the old shared input to
use the same script as the new output, so changing the attestation to the new
keys alone does not resolve the contract. This confirmed interoperability
limitation is tracked in [Beignet issue 1871](https://github.com/coreyphillips/beignet/issues/1871).
The native compatibility policy now retains the funding key on private channels
from creation onward. It is persisted with an old-reader rejection marker and
applied consistently to native funding and commitment signatures. The passing
fixture preserves the payer's strict verification and uses no address fallback.

`CHICORY_TEST_OFFLINE=1` prepares a funded concurrent-v2 reservation, stops the
phone, restarts the primary, pays externally, restarts the primary again, and
reopens the phone twice to require one credit and one completed Activity row.
Run it with `CHICORY_ENABLE_OFFLINE=1` to opt the example into native offline
admission. All ten checks passed against the installed phone engine. The
example's explicit `splice_in` administration command provides its required
inbound headroom; offline quotes do not allocate those funds. This covers a
single fixed-amount concurrent-v2 reservation and disconnected delegated
settlement, not every crash point or onchain phone recovery scenario.

`CHICORY_TEST_OFFLINE_CONCURRENT=1` additionally sends and receives ordinary
Lightning payments while the voucher book is ACTIVE. `CHICORY_TEST_OFFLINE_UNPAID=1`
instead explicitly closes an unpaid reservation, preserves DRAINING through
both restarts, force-closes the actual commitment and confirms its exact voucher
timeout before requiring a fresh usable home. `CHICORY_TEST_OFFLINE_AUTO_EXPIRE=1`
selects the same unpaid lifecycle using the real 600-second invoice expiry and
120-second grace period. It asserts the reservation remains ACTIVE during grace
and waits for the normal runtime timer to close admission without an explicit
close command. This takes more than twelve real minutes. Both unpaid modes
require `CHICORY_TEST_OFFLINE=1` and `CHICORY_ENABLE_OFFLINE=1` and run separately
from the paid-concurrent mode. Use a fresh disposable provider directory for
each run; the fixture creates and removes these directories automatically.

`CHICORY_TEST_SEND_MAX=bech32`, `bech32m`, or `p2wsh` adds an exact reviewed
maximum payout to the selected destination type. It checks the old funding
input, new usable home and actual output, then restarts both endpoints and
checks one completed Activity entry. The example does not negotiate a reserve
waiver, so the installed phone correctly retains its 1,000-sat reserve.
`CHICORY_TEST_DRAIN=1` adds a confirmed 20,000-sat loose coin below the automatic
channelization floor, drains by cooperative close and sweep, and restarts both
endpoints before confirmation. A fresh JIT receive must complete on a new home
while the old drain remains unconfirmed. After confirmation, one drain Activity
entry must account for both transactions and a later 1,000-sat deposit must
remain untouched. These funded cases passed in the record below.

Run the two
funded fixtures sequentially. Portable JavaScript qualification does not cover
the iOS application lifecycle, native storage adapter, simulator or Iroh.

The native JIT and installed portable fixtures exposed a Beignet payment-history discrepancy: the
payment record reports the gross 20,000 sats while the committed channel
balance receives 19,880 sats after the quoted 120-sat fee. The installed
wallet-core maps that payment amount directly into Activity and reports its
fee as zero. The portable
fixture therefore records Activity amount and fee separately and still
requires the exact 19,880-sat channel and wallet balances. Tracking issue:
[Beignet #1869](https://github.com/coreyphillips/beignet/issues/1869).

An initial Electrum-backed run identified a remote anchor commitment fee
mismatch: Beignet's channel open offered 253 sat/kw while LDK's Electrum fee
estimator required at least 500 sat/kw. Bitcoin Core's native fee estimator
uses the mempool minimum for this particular lower-bound target. The fixture
therefore uses Bitcoin Core for the provider while Beignet clients use
Electrum on the same regtest chain. This choice does not establish that the
Electrum-backed provider accepts the same Beignet-funded open. Core can also
reject the fixed phone fee when its mempool minimum rises. The native safety
check remains in place; see [Beignet issue 1873](https://github.com/coreyphillips/beignet/issues/1873).

- `beignet-portable-engine/scripts/regtest-harness.cjs` creates real portable
  runtimes, durable volumes, the wallet client, and byte transports. Replace
  its provider startup with the Rust process while preserving phone code.
- `scripts/regtest-channelize.cjs` covers deposit splicing, first channel
  funding, and a second phone's direct-funded payment.
- `scripts/regtest-ffor.cjs`, `scripts/regtest-ffor-native.cjs`, and
  `scripts/regtest-send-max.cjs` cover the corresponding acceptance scenarios.
- Chicory `native-tests/OfflineReceive.tsx` provides a command-driven isolated
  native entry. `native-tests/iroh-primary.cjs` provides a separate transport
  qualification helper whose provider startup also needs adaptation.

The existing portable fixtures default to Docker container `bitcoin`, Core RPC
port `43782`, and Electrum `127.0.0.1:60001`. They accept
`BEIGNET_REGTEST_BITCOIN`, `BEIGNET_SOURCE_DIR`, `BEIGNET_WALLET_CORE_DIR`, and
`BEIGNET_RELAY_DIR`. The alternative local network supplied for this work is
`mint.local:60401` with plaintext Electrum and the control API described at
`http://mint.local:3022/api/openapi.json`. Adapt chain-control calls to that API
only after reading its schema and verifying regtest. Do not mix services from
different chains in the same test.

## Verification record

Funded regtest runs on 2026-10-25 UTC produced these measured results. Each
used Bitcoin Core for the native primary and Electrum for the unchanged
Beignet or installed portable clients. The runner checked `chain=regtest`
before funding disposable wallets.

| Run | Measured result | Evidence |
| --- | --- | --- |
| Native JIT subset, 03:30:16 to 03:30:22 UTC | 12 checks passed: BOLT 8, opaque relay forwarding with authenticated sender, correlated offline refusal, confirmed payer channel, exact 120-sat skim quote, excessive-request refusal, invoice authorization, provider restart and authorization replay, a forwarded payment opening one receiver channel and delivering 19,880 sats, and full 65,531-byte backup retrieval on reconnect and provider restart. | [JSON](qualification/native.json), `passed: true`; Beignet 0.32.2. |
| Installed portable default, 03:31:05 to 03:31:11 UTC | 6 checks passed: pairing, confirmed external payer channel, reviewed unified JIT receive, completed Activity with exact 19,880-sat wallet and channel balances, portable runtime reopen retaining the paid request and channel, and a 3,000-sat Lightning send to the native primary. Available balance was 18,880 sats. | [JSON](qualification/portable.json), `passed: true`; Chicory 0.7.4, engine upstream 0.32.1. |
| Installed portable with `CHICORY_TEST_SPLICES=1`, 03:31:53 to 03:32:05 UTC | All 6 default checks plus confirmed 30,000-sat deposit channelization into the existing home and a confirmed splice-out paying exactly 2,000 sats passed. Activity reported gross 20,000 sats and zero fee for the JIT payment; committed and wallet balance was 19,880 sats. | `/tmp/chicory-portable-splice.log`; splice-out txid `f18ccd7270b2baca361b902db949bbc0da1680c3e4c23ffa120ca783e316d5e7`. |
| Installed portable splice safety regression, 03:40:11 to 03:40:37 UTC | All 11 checks passed. The native primary retained its old active funding and value at zero confirmations, retained that requirement after its process restarted, still retained old funding at five confirmations, and activated the deposit candidate at six. A subsequent splice-out paid exactly 2,000 sats. | [JSON](qualification/splice-confirmations.json), `passed: true`; deposit candidate `00f5c18fa2313ce74c8e6cfb660964be3c86744172ea4e0dd67681919f93bb00`; splice-out `23cd43ff1b10a220a501d5a03c009a6a790cd2b2c075a97907459ff10c146643`. |
| Native two-part JIT, 03:49:48 to 03:49:55 UTC | All 4 checks passed. Beignet 0.32.2 sent distinct 10,000-sat HTLCs to the same intercept SCID after a provider restart preserving registration. Native forwarding events and distinct receiver HTLC ids proved 9,880 and 10,000 sats arrived through one new channel, with one 120-sat skim fee. Committed receiver balance was exactly 19,880 sats. | `/tmp/chicory-mpp-evidence.json`, `passed: true`; payment hash `9437c162f5875633678b683d453c7a138533e03c203a032136944ad6fc03a079`. |
| Installed portable fresh-channel direct funding, 03:50:25 to 03:51:36 UTC | All 7 checks passed: the 6 default checks and a 15,000-sat direct-funded first channel using the native confirmed v2 acceptor. A payer's confirmed 20,000-sat coin funded the exact attested output; receiver capacity and local balance were both 15,000 sats. The receipt preimage matched the signed request hash and payer Activity completed for 15,000 sats. Existing-home direct funding was explicitly skipped. | `/tmp/chicory-portable-fresh-evidence.json`, `passed: true`, `directFundingScope: initial-channel-only`; funding txid `97f0cefc54dcdeadd71837f392bd9447d10b03b553029eb3cd194e507fefcea0`. |

Later funded runs extended that record:

| Run | Measured result | Evidence |
| --- | --- | --- |
| Installed portable complete direct funding, 04:06:44 to 04:09:00 UTC | All 10 checks passed. Existing-home direct funding added exactly 5,000 sats using the previous funding input; initial direct funding created a 15,000-sat v2 channel. Both payers verified receipts and attested outputs. Both native channels became usable with matching funding outpoints, and each receiver completed a subsequent 1,000-sat Lightning spend. | `/tmp/chicory-portable-direct-full-evidence.json`, `passed: true`, `directFundingScope: existing-home-and-initial-channel`. |
| Installed portable existing-home JIT splice, 04:17:17 to 04:17:29 UTC | All 7 checks passed. One incoming HTLC triggered one splice from 40,000 to 90,000 sats. One 130-sat JIT fee left an exact 29,870-sat receiver increase. The native primary and installed phone agreed on the replacement funding, usable status and channel value, retaining one home. | `/tmp/chicory-portable-jit-splice-evidence.json`, `passed: true`; funding txid `26d96d71400052b651dc84bc61fef2f99fd8ad20f45502f30376c380f170cc99`. |
| Installed portable JIT lease and input-selection checkpoint, 04:21:37 to 04:21:48 UTC | All 7 JIT splice checks passed after the persisted global funding lease and confirmed-input admission changes. | [JSON](qualification/jit-splice.json), `passed: true`; funding txid `9664354687f1f8446b403cd4803cd29992f8dc9d27e28cc0eb22b88586b5e7ee`. |
| Installed portable Taproot send-max, 04:23:32 to 04:24:04 UTC | All 8 checks passed. Actual payout was the reviewed 15,301 sats; the configured reserve retained 1,000 sats. The home and one completed Activity entry survived phone and primary restarts. | [JSON](qualification/send-max-p2tr.json), `passed: true`. |
| Installed portable P2WPKH send-max, 04:24:34 to 04:25:06 UTC | All 8 checks passed. Actual payout was the reviewed 15,337 sats with 1,000 sats retained, followed by both endpoint restarts. | [JSON](qualification/send-max-p2wpkh.json), `passed: true`. |
| Installed portable P2WSH send-max and drain, 04:26:49 to 04:27:29 UTC | All 11 checks passed, including matching usable native funding before and after send-max restart. The 15,301-sat P2WSH payout retained 1,000 sats. Cooperative close and loose-coin sweep broadcast before confirmation, survived both restarts, and a fresh JIT receive delivered 4,895 sats while old drain transactions remained unconfirmed. One drain Activity completed after confirmation and excluded a later 1,000-sat receipt. | [JSON](qualification/send-max-p2wsh-and-drain.json), `passed: true`. |
| Installed portable initial deposit, 04:40:15 to 04:40:23 UTC | All 4 checks passed. A 30,000-sat deposit created one 29,475-sat phone-funded channel. It remained unusable before confirmation through primary restart, then completed a 1,000-sat spend and phone reopen with 28,475 sats. | [JSON](qualification/initial-deposit.json), `passed: true`. |
| Installed portable empty-phone recovery, 04:47:15 to 04:47:44 UTC | All 8 checks passed. After the primary restarted, a new phone volume imported its peer-storage capsule, restored the original funding and exact 16,880-sat balance, and retained the reference permanent recency hold with zero available balance. | [JSON](qualification/recovery-held.json), `passed: true`. |
| Installed portable recovery sweep, 04:50:35 to 04:51:10 UTC | All 9 checks passed. The empty phone imported its capsule and kept the safety hold. The primary broadcast its current commitment; the restored phone swept the exact 16,880-sat output into a 15,780-sat wallet coin, paying the measured 1,100-sat fee without signing stale channel state. | [JSON](qualification/recovery-sweep.json), `passed: true`. |
| Installed portable offline receive, 05:10:07 to 05:10:26 UTC | All 10 checks passed. The unchanged phone activated one 5,000-sat concurrent-v2 voucher. With the phone stopped, a restarted native primary settled the external payer. After another primary restart the phone recovered the receipt, increased its balance from 16,880 to 21,880 sats, and preserved exactly one completed Activity row and a usable zero-HTLC home through a second reopen. | [JSON](qualification/offline.json), `passed: true`. |
| Native existing-home multipart splice, 05:11:06 to 05:11:15 UTC | All 5 checks passed. Two genuine 15,000-sat shortfalls on the real home alias triggered one 40,000-to-90,000-sat splice. Native forwarding events and distinct receiver HTLC ids proved 14,870 plus 15,000 sats arrived, one 130-sat JIT fee and two 1-sat routing fees were earned, and both peers retained one usable home with matching funding. | [JSON](qualification/existing-home-mpp.json), `passed: true`. |
| Installed portable concurrent offline receive, 05:13:31 to 05:13:51 UTC | All 11 checks passed. With an ACTIVE voucher book, the phone sent 1,000 sats and received 1,200 sats through ordinary Lightning before going offline. A restarted primary settled a 5,000-sat external payment; another primary restart and two phone reopens preserved exactly one credit, a 22,080-sat balance and one usable home with no remaining HTLC. | [JSON](qualification/offline-concurrent.json), `passed: true`. |
| Installed phone conflict recovery, 05:45:22 to 05:46:49 UTC | All 10 checks passed. A disposable payer replaced only its own nonshared splice input. Five confirmations preserved the candidate through primary restart. Six restored matching usable original funding, and both endpoint restarts were followed by a successful 1,000-sat Lightning payment. | [JSON](qualification/conflict.json), `passed: true`. |
| Native iOS wallet, 05:51:41 to 05:52:25 UTC | All 11 checks passed in Hermes using Chicory's native TCP, cryptography, Keychain and SQLCipher adapters. Real app restarts retained paid Activity and channel state. Ordinary payments with an active offline book, offline settlement across primary restarts and exactly one 5,000-sat recovered credit all passed. This uses an isolated test scene delegate, not the normal application screens. | [JSON](qualification/ios.json), `passed: true`; native binary SHA256 `31c5f546513e7a3d348e4c8dd52ddc98eb2783df514f4cd620e8245267188b7b`. |
| Direct Iroh wallet, 05:54:24 to 05:55:00 UTC | All 11 installed-wallet checks passed through the separate byte bridge to native LDK, including runtime/primary restarts and offline receipt recovery. The fixture waits nine seconds with a stable home before offline setup to avoid the confirmed installed-client watchdog bug. Public relays and native iOS Iroh are not covered. | [JSON](qualification/iroh.json), `passed: true`; [watchdog issue 1872](https://github.com/coreyphillips/beignet/issues/1872). |
| Unpaid offline lifecycle, 05:58:07 to 05:59:05 UTC | All 11 checks passed at this checkpoint. Explicit admission close retained an unpaid voucher in DRAINING through both restarts. The primary force-closed its actual current commitment, the exact 5,000-sat voucher resolved through a real timeout transaction with six confirmations, and another pair of restarts was followed by a fresh 9,890-sat JIT home. The unpaid invoice never acquired a completed Activity row. This tests explicit close, not the automatic wall-clock expiry trigger. | [JSON](qualification/offline-unpaid.json), `passed: true`; native binary SHA256 `617a88077fe5e3a0acd0ab2c2b0beecf36a11756c6be75e5e305b7578f38f668`. |

Later checkpoints were checked after the native retirement guards were complete:

| Run | Measured result | Evidence |
| --- | --- | --- |
| Complete direct funding, 06:03:41 to 06:05:59 UTC | All 10 checks passed again, including existing-home and initial-channel receipts, exact outputs, matching usable funding and a subsequent Lightning spend from each channel. | [JSON](qualification/final-direct-funding.json); binary SHA256 `e557becd6e07d67c202e98437f7d4c0dede9d9f28281103d60895378379498b0`. |
| New-home multipart JIT, 06:10:34 to 06:10:40 UTC | All 4 checks passed again. Two distinct 10,000-sat parts after primary restart delivered 9,880 and 10,000 sats through one home with one 120-sat fee. | [JSON](qualification/final-mpp.json). |
| Confirmed splice conflict, 06:12:20 to 06:12:40 UTC | All 10 checks passed again at this checkpoint. The candidate remained pending at five confirmations through restart, original funding became usable at six, and both restarts preceded a successful 1,000-sat Lightning payment. | [JSON](qualification/final-conflict.json). |
| Direct Iroh after bridge failure handling, 06:18:10 to 06:18:43 UTC | All 11 wallet checks passed again, including ordinary payments with an active reservation, offline settlement across primary restarts and exactly one recovered credit through two phone reopens. The separate bridge suite passed all 11 tests, including fatal accept/refuse cleanup and a native BOLT 8 handshake. | [JSON](qualification/final-iroh.json); binary SHA256 `d44933ce17b3068bbc466f58e72ea99ee34d42965fa656d02dc3b033ac5db7f5`. |

Selected successful machine-readable records are retained in
[`qualification/`](qualification/). The older runs qualify the stated checkpoints,
not an assertion that every later source revision reran every scenario. The
records contain only public test identifiers, amounts, hashes and measured
outcomes; temporary wallet directories and secret payment material are excluded.

A longer automatic-expiry qualification exposed a separate monitor persistence
boundary after these checkpoints. Once its final on-chain claim matured, the
normal periodic snapshot policy could leave the authenticated resolution proof
only in memory. A later FFOR journal delta was durable but could not replay over
the older snapshot. The native incremental persister now writes the complete
monitor whenever the journal contains a chain removal, preserving the original
update ID and withholding completion until that full write succeeds. Native
signed timeout and fulfillment regressions exercise the actual asynchronous
persister and keep the independent proof check intact. Custom incremental
persisters must honor the new `requires_full_monitor_persistence` contract.

The corrected real-time rerun passed all 13 checks from 06:42:29 to 06:55:20 UTC.
The unchanged installed wallet retained the voucher after its actual 600-second
invoice expiry, closed admission automatically after the 120-second grace
period, and preserved DRAINING through both endpoint restarts. The real
5,000-sat voucher timeout reached six confirmations. Another primary restart
succeeded, and a fresh JIT home received 9,890 sats without any completed
Activity row for the unpaid invoice. The [public evidence](qualification/offline-auto-expire.json)
records a 721,780 ms wall-clock wait and the native binary hash. No test clock
or explicit admission-close command replaced the timer in this run.

The baseline splice run mined immediately and therefore did not establish
safe handling of unconfirmed peer contributions. A subsequent source audit
found that stock `FundingScope::for_splice` inherited depth zero from the
original zero-conf channel, allowing `splice_locked` at signature exchange.
The corrective native candidate floor passed the separate funded
zero/five/six-confirmation restart regression above. The inbound policy is
read from the current provider configuration even for restored channels and
persists the effective floor in each candidate. It covers all inbound splice
contributions, including negative contributions. Beignet's unpaired
direct-funding path separately requires its requested lock-depth TLV `65537`
to be echoed exactly. The native acceptor validates one big-endian `u16` in
the supported range 1 through 6, echoes the requested value, and applies the
greater of its configured local floor and the negotiated depth. This does
not claim that native outgoing splices negotiate the extension.

The installed engine bundle SHA256 was
`05cdb752e1007532edc1366ea14cbf98a96825885a62d47d6001f74c1bed229d`.
The installed wallet-core `src/index.js` SHA256 was
`4a79550c91ac05303d85d28fe0b5daf4c2a05da97e713a83db54012f7e9a655e`.
No phone package was patched for these runs. Activity completion and balances
passed; accurate net Activity accounting remains the confirmed upstream issue
described above.

These results do not qualify every FFOR crash or onchain phone-recovery path,
live crashes during every partial multipart collection or funding boundary,
complete coverage, an exhaustive fuzz campaign, or production security. The later
transport and iOS records extend this historical scope. Subsequent changes to the
native channel engine require rerunning
the funded fixtures before relying on this record for that later tree.

## Normal dependency features

The early example-based fixtures enabled `lightning/_test_utils` through the
root package's dev dependencies. A separate, reproducible host now lives at
[`tools/chicory-primary`](../tools/chicory-primary/README.md). It shares the
unchanged driver source, supplies both local native patches, and uses normal
consumer dependencies. Its pinned lock retains the root dependency versions
and checksums. The [build evidence](qualification/normal-build.json) records
only `default`, `grind_signatures`, and `std` on Lightning, with no `_test_utils`
in the resolved dependency graph.

The test feature changes persisted `PaymentPathFailed` event fields and disables
some ordinary gossip freshness and rebroadcast checks. It does not introduce an
alternate FFOR, direct-funding, confirmation, fee or persistence implementation.
Nevertheless, the normal-feature runs use fresh provider state. Do not reuse a
provider database across these feature sets based on the successful protocol
fixtures alone. Private-channel qualification also does not cover public gossip
propagation.

A separate unfunded normal-host check reached a public Iroh relay and completed
native BOLT8 authentication, but the transport switched from relay to direct IP
during the exchange. The strict relay-only qualification therefore failed. The
pinned addon cannot disable IP transport through its public API, and its path
watcher aborted during diagnostics. The bridge does not use that watcher. See
[the transport assessment](../tools/chicory-iroh/README.md) for the distinction
between that historical mixed-path check and the later forced-relay qualification.
A container-scoped UDP exclusion now supplies reproducible relay-only tests
without changing the host firewall. This earlier check used the supplied
`mint.local:60401` Electrum server read-only; funded scenarios use Docker regtest.

| Normal host run after the persistence fix | Measured result | Evidence |
| --- | --- | --- |
| Explicit unpaid lifecycle, 06:56:14 to 06:57:04 UTC | All 11 checks passed. Actual voucher timeout, both post-timeout restarts, a fresh 9,890-sat JIT home and no unpaid credit. | [JSON](qualification/normal-offline-unpaid.json). |
| Paid concurrent offline receive, 06:57:26 to 06:57:47 UTC | All 11 checks passed. Ordinary 1,000-sat send and 1,200-sat receive while ACTIVE, offline settlement across primary restarts, and exactly one 5,000-sat credit through two phone reopens. | [JSON](qualification/normal-offline-concurrent.json). |
| Complete direct funding, 06:58:17 to 07:00:33 UTC | All 10 checks passed. Both existing-home and initial-channel deposits delivered exact amounts with verified receipts and matching usable native funding, followed by a successful 1,000-sat Lightning spend from each channel. | [JSON](qualification/normal-direct-funding.json). |

## Build and regression results

These checks were run locally with Rust 1.99.1. The long integration fixtures use
Bitcoin Core 27.2 and the locally built electrs server. Build outputs, downloaded
tools and fuzz corpora are excluded from the branch.

| Check | Measured result |
| --- | --- |
| `cargo build --all-targets --features chicory --locked` | Passed after the final driver change. Compiler warnings remain. |
| Default-feature library tests | 124 passed, zero failed. |
| `cargo test --features chicory --lib` | 211 passed, zero failed after adding manual/JIT funding exclusion. |
| `cargo test --features chicory --doc` | 13 passed, zero failed. |
| Standalone normal-dependency host | Built successfully with no `_test_utils`; pinned dependency versions and checksums match the root lock. |
| Native Lightning library suite | 1,289 passed, zero failed, nine existing upstream tests ignored, after the chain-proof persistence fix. |
| Patched liquidity library suite | 63 passed, zero failed. |
| All-target checks with default features and with `chicory uniffi` | Both passed. |
| Standard Rust integration suite | 52 passed on the initial run; six startup/address/timing failures all passed on the lower-concurrency retry. This was not one clean uninterrupted suite run. |
| Multi-address wallet suite and chain reorg property test | All 110 address tests passed in 2,422.40 seconds. The reorg test passed its five generated cases in 233.77 seconds. |
| Iroh bridge tests with native addon and BOLT 8 | 11 passed, zero failed after the fatal accept-loop fix. |
| Native FFOR libFuzzer campaign | 4,118,637 executions in 121 seconds, no finding. |
| Custom wire libFuzzer campaign | 321,330 executions in 121 seconds, no finding. |
| Root formatting and whitespace checks | `cargo fmt -p ldk-node --check` and `git diff --check` passed. Stable rustfmt reports the existing nightly-only configuration options. Full workspace formatting also reports native-fork style differences and is not a passing check. |
| Root Clippy with `--no-deps` | Passed with warnings. |
| Full dependency Clippy | Failed on seven unchanged upstream Lightning lint errors: four `erasing_op` and three `never_loop`. These are not described as a clean lint run. |

The full Clippy failure sites were compared with the pinned upstream 0.2.7
source. No lint suppression or unrelated upstream rewrite was added to make
that command appear green. These tests and bounded fuzz campaigns do not prove
complete line or branch coverage, absence of cryptographic defects, or a
production security audit. Miri, Loom, real mainnet funds, physical iPhones and
physical Umbrel hardware are not qualified by these local records. See the later
transport and normal iOS UI records for their measured scope.


## Local client compatibility fixes

The original installed phone is retained in the historical records above. The
final local candidate also includes a reviewed portable-engine patch because
three client defects prevent consistent operation across native fee estimates,
splices, and connection timing:

- New v1 and v2 channels select a fresh independent fee estimate for their initial
  commitment. The fee is at least the explicit configured rate and 253 sat/kw.
  An enabled estimator without a fresh sample triggers one bounded refresh and
  refuses the open before allocating channel state if it remains unavailable.
  An explicit v2 rate remains explicit, and existing channels are unchanged.
- Shared funding inputs reserve the conservative 386 weight units when estimating
  a funding fee, but the pre-signature audit uses the attainable 382-unit minimum.
  This admits native low-R signatures without weakening other inputs' weight,
  ownership or witness checks. The final witness is not known at this audit;
  senders remain responsible for the actual signed transaction fee.
- The reconnect watchdog retries an incomplete channel reestablishment exchange.
  A healthy home intentionally held by a splice or offline custody transition no
  longer triggers a disconnect merely because it cannot currently carry HTLCs.
  Retries remain bounded and stale callbacks cannot disconnect a new connection.

The patch is [portable-engine-primary-compatibility.patch](../patches/portable-engine-primary-compatibility.patch).
It applies to portable-engine base `67bc9cf0ba3e55fa1e1d7ad73e360bb04321a62c`.
The local source branch ends at `c9acc05f61899468f4eefd71d599d0de0bea9190`.
The exact reviewed source and built bundle hashes are in
[the installation manifest](../scripts/chicory-local-engine-manifest.json).
After building that local source, install it into Chicory with:

```sh
node scripts/chicory-install-local-engine.cjs --check /absolute/path/beignet-portable-engine /absolute/path/chicory
node scripts/chicory-install-local-engine.cjs /absolute/path/beignet-portable-engine /absolute/path/chicory
```

The installer preflights all files, preserves the original bundles privately,
and refuses unrelated installed edits. Package reinstallation may overwrite the
local bundles; rerun the installer and rebuild the iOS application afterwards.
This is a local dependency override, not a published package update. Wallet-core
is unchanged. The matching initial-fee and shared-input changes are also saved
on the local Beignet branch, with 448 and 644 targeted regression tests passing
respectively. The combined portable build passed all 229 tests, including four
watchdog regressions. Type checks passed; upstream lint warnings remain.

The normal iOS application required a separate scene lifecycle correction for
iOS 27 SDK builds. The [scene patch](../patches/chicory/ios27-scenes.patch) retains
the app-switcher privacy cover and cold/warm payment-link delivery. See the
[iOS qualification](chicory-ios-testing.md) for normal UI and native-adapter scope.

Relevant public issues are [Beignet 1872](https://github.com/coreyphillips/beignet/issues/1872)
(reconnect watchdog), [1873](https://github.com/coreyphillips/beignet/issues/1873)
(initial commitment fee), and the existing [359](https://github.com/coreyphillips/beignet/issues/359)
(shared-input fee audit); [Chicory 73](https://github.com/coreyphillips/chicory/issues/73)
(scene lifecycle), [74](https://github.com/coreyphillips/chicory/issues/74)
(gross JIT Activity accounting), and [75](https://github.com/coreyphillips/chicory/issues/75)
(initial-fee dependency integration), and [76](https://github.com/coreyphillips/chicory/issues/76)
(duplicate Home action keys). JIT Activity still shows the original gross
amount and zero fee where the home receives the net amount. This existing client
accounting issue also occurs with a Beignet primary and is not hidden by changing
the native provider's fee or balance.

## Native administration and local Umbrel package

[`tools/ldk-node-daemon`](../tools/ldk-node-daemon/README.md) runs the native library
with normal dependency features and a private bounded JSONL administration pipe.
It supports explicit networks and chain backends, exclusive private storage,
backend genesis validation, durable public event history, and secret-free offline
status. Manual opens, splices and Bitcoin sends coordinate with JIT funding through
`Node::with_chicory_wallet_operation`. Event history is persisted before native
acknowledgment; a persistence fault stops the node instead of silently consuming
its events. The daemon's seven focused tests, the library funding exclusion test,
and the native durable-epoch status regression pass. The all-target check with
`chicory uniffi` and 13 doctests also pass. The [administration check record](qualification/native-daemon.json)
retains counts, source revision, binary hash and installer refusal checks.

The separate local `ldk-node-umbrel` checkout contains the authenticated dashboard,
local image loader, Umbrel manifest and Docker Compose deployment. It uses this
native daemon, supports AMD64 and ARM64, and defaults the creation form to Mainnet.
Provider funding and offline admission require explicit configuration. The local
package README contains the exact image checksums, installation, pairing, backup,
and qualification instructions. No source, image or release is published.

## Extended transport and iOS qualification

The following records extend the earlier scope. Historical records retain their
original client and native hashes. The local client corrections above do not
retroactively change those earlier test results. Every funded scenario uses
disposable regtest funds.

| Scenario | Measured result | Evidence |
| --- | --- | --- |
| Forced public Iroh relay with explicit address | All 11 installed-wallet baseline and concurrent offline checks passed. Endpoint UDP was blocked inside isolated containers, with before/after firewall counters and unprivileged endpoint processes. Provider restarts and two phone reopens retained exactly one offline credit. No artificial offline-setup delay. Original installed client. | [Wallet JSON](qualification/forced-relay-wallet.json), [transport evidence](../tools/chicory-iroh/relay/qualification.json). |
| Public discovery with a bare Iroh endpoint URI | All 11 baseline and concurrent offline checks passed. No relay URL or direct address was supplied to the wallet. Direct UDP remained blocked, all endpoint containers and networks were removed, and the final 22,080-sat balance contained one offline credit. Combined local client, zero artificial delay. | [JSON](qualification/relay-discovery.json). |
| Normal iOS application screens | Actual receive, send, background privacy cover, primary restart while backgrounded, reconnect and cold app restart passed. A 20,000-sat JIT payment credited 19,880 sats; sending 1,000 left 18,880. A later 5,000-sat offline payment while the app was terminated recovered once after two primary restarts, leaving 23,880 through another cold reopen. | [UI observations](qualification/ios-normal-ui.json), [controller results](qualification/ios-normal-ui-controller.json), [received screen](qualification/ios-normal-ui-received.png), [offline screen](qualification/ios-normal-ui-offline.png), [privacy screen](qualification/ios-privacy.png). |
| Normal iOS cold/warm payment links | All four Bitcoin and Lightning URI delivery cases reached the correct 1,000-sat Send form with explicit review. This separate empty, disconnected wallet submitted no payment and retained zero Activity rows. It tests delivery and review boundaries, not a funded link payment. | [JSON](qualification/ios-payment-links.json). |
| Portable same-key onion fallback | All 11 baseline and concurrent offline checks passed with the provider Iroh endpoint stopped. Five Iroh attempts established zero connections; the public Tor fallback delivered the full wallet flow, ending at 22,080 sats with one offline credit. Disposable Tor container and network removal were verified. | [JSON](qualification/onion-fallback.json). |
| Native iOS Iroh through a forced public relay | All 11 baseline and concurrent offline checks passed with Chicory's production native Iroh, cryptography, Keychain and SQLCipher adapters. Provider-side container rules prevented direct UDP throughout four relay-only sessions; final cleanup was verified. No factory override in the phone and no artificial setup delay. | [JSON](qualification/ios-forced-relay.json). |
| Native iOS same-key onion fallback | All 11 baseline and concurrent offline checks passed with the Iroh provider stopped. The production native Iroh and Tor adapters selected the persisted same-key onion fallback, retained exact payments through phone and primary restarts, and recovered one offline credit. Disposable Tor container and network removal were verified. | [JSON](qualification/ios-onion-fallback.json), [native app hashes](qualification/ios-native-builds.json). |
| Native iOS direct funding with an Electrum primary | All 10 checks passed using the combined local client. An existing home received 5,000 sats and a separately signed fresh phone created a 15,000-sat v2 channel. Both receipts and exact funding outputs were verified; both receivers then completed a real 1,000-sat Lightning spend. | [JSON](qualification/ios-electrum-direct-funding.json). |
| Packaged Linux AMD64 primary | All six funded baseline checks passed through authenticated dashboard HTTP and the packaged native daemon: exact 19,880-sat JIT receipt, restored phone state and outgoing Lightning payment. | [JSON](qualification/umbrel-amd64-funded.json). |
| Packaged Linux ARM64 primary | All 11 concurrent offline checks passed through the dashboard and packaged native daemon, including ordinary payments while ACTIVE, payment with the phone stopped, primary restarts and two phone reopens with exactly one 5,000-sat recovered credit. | [JSON](qualification/umbrel-arm64-offline.json). |

The packaged fixture's `primaryBinarySha256` identifies its small authenticated
HTTP adapter, not the native executable. The dashboard package's image and
[native-binary provenance record](qualification/umbrel-images.json) supplies those hashes. Both images also passed
native sync, Iroh startup, identity preservation and graceful whole-container
shutdown checks. AMD64 executed under Docker Desktop emulation on this ARM64
host. No physical Umbrel installation was performed.

The UI runs used an isolated iPhone Air simulator with iOS 27.0 and Xcode 27.1.
The original wallet application and its funds were not reused. These are real
normal application screens; the separate native protocol harness covers the
adapter and storage paths without claiming to exercise every screen.
