# Native iOS qualification

The simulator fixture runs Chicory's installed wallet engine and wallet-core in
Hermes with its real native TCP, cryptography, Keychain and SQLCipher adapters.
Only a separately signed `com.chicory.primaryqualification` app is installed.
Its test entry accepts a small wallet-operation whitelist from a loopback
controller. It refuses non-regtest wallets and accepts only loopback TCP or an
explicit Iroh endpoint with an HTTPS public relay in the `relay.n0.iroh.link`
domain. Optional onion fallback is restricted to one exact disposable service
registered by the controller, with the same Lightning key as the Iroh primary.
No recovery phrase or signing key is exported to the controller.

There are two build modes. The default `harness` mode qualifies native wallet
execution and process recovery using a bounded test entry and its own scene
delegate. The `wallet` mode bundles Chicory's ordinary `index.js` and production
scene lifecycle for actual UI testing. Neither mode qualifies physical-device
power management, notifications, or biometric lock. Native Iroh uses the real
device adapter when enabled; a separate transport result is required before
claiming that path passed.

## Build

Use a Chicory checkout with its pinned JavaScript packages and CocoaPods
dependencies already installed, plus Xcode. The tested CocoaPods version was
1.16.2. The SDK was iOS Simulator 27.1 and the runtime was iOS 27.0. Newer SDKs
require raising the deployment target of older pods for this test build; the
builder supplies 15.1 without changing their checked-in source.

```sh
CHICORY_SOURCE_DIR=/absolute/path/to/chicory \
CHICORY_IOS_BUNDLE_ID=com.chicory.primaryqualification.run1 \
  sh scripts/chicory-ios-build.sh > /tmp/chicory-ios-build.log 2>&1
```

In harness mode the builder temporarily supplies `native-tests/LdkPrimary.tsx`,
the test scene delegate and a scene manifest, then restores the original source
files on exit. Wallet mode leaves the application entry and scene unchanged.
It refuses to overwrite an existing qualification entry. It does not run
CocoaPods or change resolved dependencies. When a newer Ruby changes only local
podspec checksums, it temporarily aligns those with the installed manifest and
restores the original lockfile on exit. Every other difference is refused.
The resulting app is under
`/tmp/chicory-primary-ios-build/Build/Products/Debug-iphonesimulator/chicory.app`.
The simulator's embedded application identifier and Keychain access group are
both scoped to `LOCALTEST.` followed by the chosen bundle identifier.

## Run

Build the normal-feature host with `cargo build --manifest-path
tools/chicory-primary/Cargo.toml` and set `CHICORY_PRIMARY_BIN` to the resulting
`tools/chicory-primary/target/debug/chicory-primary-local`. Select an already
booted disposable simulator using
`xcrun simctl list devices booted`. Start the controller with that device's
identifier. The underlying fixture requires the same Docker regtest services
as the portable test, and funds only newly created test wallets.

```sh
CHICORY_TEST_IOS=1 CHICORY_IOS_DEVICE_ID=YOUR_SIMULATOR_UDID \
CHICORY_IOS_BUNDLE_ID=com.chicory.primaryqualification.run1 \
CHICORY_ENABLE_OFFLINE=1 CHICORY_TEST_OFFLINE=1 \
CHICORY_TEST_OFFLINE_CONCURRENT=1 \
BEIGNET_EVIDENCE_FILE=/tmp/chicory-ios-evidence.json \
  node scripts/chicory-portable-interop.cjs
```

While the controller waits, install and launch the isolated app:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcrun simctl install YOUR_SIMULATOR_UDID \
  /tmp/chicory-primary-ios-build/Build/Products/Debug-iphonesimulator/chicory.app
xcrun simctl launch YOUR_SIMULATOR_UDID com.chicory.primaryqualification.run1
```

The controller performs real app termination and relaunch at each phone restart
boundary. It waits for the replacement process before sending another command.
It also restarts the native primary around offline settlement. The fixture
supports baseline and offline scenarios, native Iroh, and direct funding.
Other portable flags are refused so that an unsupported path cannot
accidentally run on the host.

For another fresh run, choose a new suffix such as `.run2` in both build and
controller commands. Uninstalling an app does not remove its Keychain entries;
reusing that identity with deleted database files correctly triggers Chicory's
missing-original-wallet protection. Never substitute the normal Chicory bundle
identifier in these commands. An existing wallet in the test app is refused
rather than erased by the controller.

For full direct-funding qualification, build and install two fresh identities,
then set `CHICORY_TEST_DIRECT_FUNDING=1` and
`CHICORY_IOS_SECOND_BUNDLE_ID` to the second identity. The initial-channel
scenario switches to that separately signed app. It never deletes the first
wallet or changes the device adapter's one-wallet-per-network policy. A
third creation attempt is refused. `CHICORY_PRIMARY_CHAIN_SOURCE` can select
the tested Electrum backend independently of the phone's Electrum settings.

For native Iroh, add `CHICORY_TEST_IROH=1`. The fixture supplies an explicit
public-relay URI and the phone selects its production native Iroh adapter.
`CHICORY_TEST_IROH_RELAY=1` is deliberately incompatible with native iOS:
that mode's firewall proof applies to a separate Node transport container.
Use `CHICORY_TEST_IROH_PROVIDER_RELAY=1` with iOS to isolate the provider
endpoint instead. Its denied UDP policy forces this connection through the
public relay while the phone retains its production native adapter.
For native onion fallback, also set `CHICORY_TEST_IROH_FALLBACK=1` and use a
fresh app identity built with the fallback-capable harness. Set
`IROH_BINDING_PATH` to the installed `@number0/iroh` 1.1.0 package directory
when it is not installed under `tools/chicory-iroh`. The fixture stops
the Iroh endpoint, publishes a disposable same-key onion service, and calls the
wallet's public `updatePrimary` operation with that exact pair. The phone uses
its native Iroh and `react-native-nitro-tor` adapters without a host factory or
SOCKS override. Bootstrap is bounded at 120 seconds and a SOCKS circuit at
180 seconds; the controller permits up to 360 seconds for that setup command.

## Normal UI qualification

Build a fresh identity with `CHICORY_IOS_MODE=wallet`, for example
`CHICORY_IOS_BUNDLE_ID=com.chicory.primaryqualification.ui1`. Launch
`scripts/chicory-ios-ui-controller.cjs` with the normal-feature host selected
through `CHICORY_PRIMARY_BIN`. It creates bounded disposable regtest peers and
writes a private loopback controller configuration to
`/tmp/chicory-ios-ui-config.json`. It never exports a recovery phrase. Configure
the regtest network, Electrum endpoint, and primary URI through the normal app
settings. The controller supplies invoices, pays the visible receive QR, and
restarts the primary. The phone uses its ordinary screens throughout.

The controller permits at most 100,000 sats of test payments, at most 50,000
sats per invoice, and one 100,000-sat capacity extension on the phone's existing
home. The extension allows the UI offline-receive policy's 50,000-sat inbound
headroom requirement to be met. It refuses the payer channel. Its authenticated
loopback API expires after 45 minutes and serializes funding and payment
requests. A deliberate controller restart retains the primary state and
creates a fresh test payer; no payer phrase is stored for recovery.

On October 25, 2026, the normal UI run used an iPhone Air simulator on iOS 27.0
and the iOS 27.1 SDK, with isolated identity
`com.chicory.primaryqualification.ui1`. The baseline JavaScript bundle SHA-256
was `a6668f71952a66c5ad939cbe2e99ef2d15dd84d97eddcdec84852d6672135cd0`.
The installed wallet packages were unchanged for this baseline. Actual screen
interaction verified:

- Primary configuration, a 20,000-sat JIT receive with a 120-sat fee, and a
  19,880-sat displayed total.
- The solid privacy cover in the app switcher, a primary restart while the
  app was backgrounded, foreground reconnection, and a normal 1,000-sat send.
- Cold app restart preserving the 18,880-sat balance and both Activity rows.
- A 5,000-sat offline invoice created through the normal receive screen.
  The phone process was terminated, the primary restarted, and an external
  payer completed the payment. After another primary restart, the normal
  wallet showed 23,880 sats and exactly one additional 5,000-sat Activity row.
  A second cold phone launch preserved the same total and three Activity rows.

Public observations are retained in
[`ios-normal-ui.json`](qualification/ios-normal-ui.json), with controller
operations in [`ios-normal-ui-controller.json`](qualification/ios-normal-ui-controller.json).
Selected screenshots show the [JIT receive](qualification/ios-normal-ui-received.png),
[offline receive](qualification/ios-normal-ui-offline.png), and
[privacy cover](qualification/ios-privacy.png). Additional original screenshots
remain under `/tmp/chicory-ios-ui-*.png`. These are test artifacts, not files
required by the runtime. Background
coverage means actual simulator background/foreground and cold process loss;
it does not establish physical iOS suspension timing.

The first normal launch exposed [Chicory issue 73](https://github.com/coreyphillips/chicory/issues/73):
an app built with this SDK aborts without UIScene adoption. The local Chicory
fix moves the React window and runtime into a single scene, keeps wallet files
excluded from stale system backups, moves the privacy cover to scene callbacks,
and forwards cold and warm links to React Native. Normal launch and privacy
behavior above passed with that fix. Cold and warm `bitcoin:` and `lightning:`
links were then exercised through the normal UI in a fresh simulator containing
only the test app. All four cases opened Send with the correct 1,000-sat amount
and an explicit Review payment control. The empty wallet remained at zero with
no Activity rows. The disconnected primary correctly prevented the explicit
Lightning review request from advancing; this test qualifies link delivery,
not a second funded payment. Evidence is in
[`ios-payment-links.json`](qualification/ios-payment-links.json), with the
four original `/tmp/chicory-ios-link-{warm,cold}-{bitcoin,lightning}.png` screenshots.
The exact local diff is retained in
[`patches/chicory/ios27-scenes.patch`](../patches/chicory/ios27-scenes.patch),
with its base revision in the adjacent `ios27-scenes-base.txt`. Apply it with
`git apply --check` first from an unchanged Chicory checkout at that revision.
The local Chicory branch is `chicory-ios-scene-lifecycle`, commit `2830fc7`.
The debug build also displayed a duplicate React child-key warning.
[Chicory issue 76](https://github.com/coreyphillips/chicory/issues/76) records the
observed warning and its exact source cause: the three sibling Home action
views share the same animation-state key. This run does not claim that
unrelated UI warning is resolved, and no payment or balance error was observed
from it.

## Patched native transport and funding qualification

The final native runs use the local engine recorded by
[`chicory-local-engine-manifest.json`](../scripts/chicory-local-engine-manifest.json),
including the initial commitment-fee, shared-input fee-audit and reconnect
watchdog fixes. They run on the disposable iOS 27.0 simulator with separate
app identities and the normal-feature primary host.

- [Electrum direct funding](qualification/ios-electrum-direct-funding.json)
  passed all 10 checks: exact existing-home and fresh confirmed-v2 funding,
  verified receipts, and a real Lightning spend from each resulting channel.
  The fresh receiver used a second app identity, preserving the first wallet.
- [Native Iroh with forced relay](qualification/ios-forced-relay.json) passed
  all 11 checks, including ordinary payments while a concurrent-v2 offline
  reservation was active, offline settlement after primary restart, and one
  correct credit after receipt recovery and another phone restart. Provider
  firewall evidence records denied UDP and four relay-only sessions, with no
  artificial setup delay. The phone used its production native Iroh adapter.

- [Native same-key onion fallback](qualification/ios-onion-fallback.json)
  passed all 11 checks with the Iroh endpoint stopped before wallet creation.
  The phone used the public settings operation to save the exact same-key onion
  endpoint and used its production native Tor adapter. JIT receive, ordinary
  payments, phone process restarts, offline settlement and exactly one recovered
  credit all passed. The disposable remote Tor container and network were
  removed. No host SOCKS override or Node transport factory was supplied.

The direct-funding and Iroh runs embedded JavaScript bundle SHA-256
`069654e531a26b1c171cfa6cac1bd6f18d9d2b5a4ed5b4f3ffcb353bf8e490c9`.
The Tor-specific harness added only the exact fallback authorization and
embedded JavaScript bundle SHA-256
`4ff16ac32b6f3799bc17601c3b77f6cf61e0620183f7a325c491a4921e264626`.
Full executable and bundle hashes for all four isolated identities are in
[`ios-native-builds.json`](qualification/ios-native-builds.json). These are
native simulator engine tests through the bounded harness; the ordinary-screen
evidence is recorded separately above.
