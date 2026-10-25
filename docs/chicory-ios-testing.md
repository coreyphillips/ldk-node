# Native iOS qualification

The simulator fixture runs Chicory's installed wallet engine and wallet-core in
Hermes with its real native TCP, cryptography, Keychain and SQLCipher adapters.
Only a separately signed `com.chicory.primaryqualification` app is installed.
Its test entry accepts a small wallet-operation whitelist from a loopback
controller. It refuses non-regtest wallets and non-loopback primary addresses.
No recovery phrase or signing key is exported to the controller.

This qualifies native wallet execution and process recovery. It does not claim
that the normal screens, background suspension, notifications, biometric lock,
or native Iroh adapter have been tested. The iOS 27 simulator requires scene
adoption, so the test build supplies its own scene delegate. Production wallet
adapters and installed package contents are unchanged.

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

The builder temporarily supplies `native-tests/LdkPrimary.tsx`, the test scene
delegate and a scene manifest, then restores the original source files on exit.
It refuses to overwrite an existing qualification entry. It does not run
CocoaPods or change resolved dependencies. When a newer Ruby changes only local
podspec checksums, it temporarily aligns those with the installed manifest and
restores the original lockfile on exit. Every other difference is refused.
The resulting app is under
`/tmp/chicory-primary-ios-build/Build/Products/Debug-iphonesimulator/chicory.app`.
The simulator's embedded application identifier and Keychain access group are
both scoped to `LOCALTEST.` followed by the chosen bundle identifier.

## Run

Build the Rust example with `cargo build --features chicory --example
chicory-primary`. Select an already booted disposable simulator using
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
currently supports the baseline and offline scenarios. Other portable flags
are refused so that an unsupported path cannot accidentally run on the host.

For another fresh run, choose a new suffix such as `.run2` in both build and
controller commands. Uninstalling an app does not remove its Keychain entries;
reusing that identity with deleted database files correctly triggers Chicory's
missing-original-wallet protection. Never substitute the normal Chicory bundle
identifier in these commands. An existing wallet in the test app is refused
rather than erased by the controller.
