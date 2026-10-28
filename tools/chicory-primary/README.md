# Local regtest primary driver

This standalone package builds the shared
[`chicory-primary.rs`](../../examples/chicory-primary.rs) driver with normal
`ldk-node` dependency features and the two required local native patches. Its own
workspace and pinned lockfile keep root dev dependencies, including
`lightning/_test_utils`, out of the default executable.

From the repository root:

```sh
cargo build --manifest-path tools/chicory-primary/Cargo.toml --locked
tools/chicory-primary/target/debug/chicory-primary-local \
  /absolute/private/path/fresh-regtest-primary 9735 \
  'rpc://RPC_USER:RPC_PASSWORD@127.0.0.1:18443'
```

This driver always uses Bitcoin regtest and listens on loopback. Configure an
actual regtest chain source and fund its returned regtest address before opening
channels. It prints newline JSON to stdout and accepts administrative commands
on stdin, for example `{"id":1,"method":"balance"}` or
`{"id":2,"method":"stop"}`. Keep stdin open while it runs.
An Electrum `tcp://host:port` URL is also accepted; the installed phone's fixed
commitment fee can be below that backend's required fee floor, as explained in
the [running guide](../../docs/chicory-running.md).

Use a fresh provider data directory when switching from `cargo run --example
chicory-primary`. Root example builds enable `_test_utils` through a dev
dependency, which changes persisted `PaymentPathFailed` event encoding and
exposes test-only APIs. Existing provider databases must not be assumed
interchangeable across those feature sets. This package uses the same driver
source without enabling that feature.

Inspect normal features with:

```sh
cargo tree --manifest-path tools/chicory-primary/Cargo.toml --locked \
  -e features -i lightning
```

The default result should list `default`, `grind_signatures`, and `std` for
`lightning`, with no `_test_utils`. `CARGO_TARGET_DIR` can select a separate build
directory. The package's local `target/` directory is ignored by Git.

This is a disposable test driver, not a deployment service. See the
[compatibility and qualification record](../../docs/chicory-primary.md) and the
[library configuration guide](../../docs/chicory-running.md) for supported
protocols, remaining limits, and configuration outside this fixture.
