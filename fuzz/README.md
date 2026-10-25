# Chicory wire parser fuzzing

The `chicory_wire` libFuzzer target exercises Beignet envelopes, all four JIT
messages, splice-conflict requests and acknowledgments, and direct-funding relay TLVs through `ldk_node::chicory::wire`. It
checks successful messages can be encoded and parsed again, including byte
limits, optional fields, canonical TLVs and truncated UTF-8 refusal strings.
Inputs are untrusted peer bytes. No network connection or wallet operation occurs.

From the repository root, with nightly Rust and `cargo-fuzz` installed:

```sh
cargo +nightly fuzz run chicory_wire -- -max_len=66000 -max_total_time=60
```

Longer fuzz campaigns should keep the same maximum input length and preserve
their corpus and crash artifacts. A successful short run is a smoke check,
not evidence of complete parser coverage or protocol safety.

A deterministic smoke harness is also available without extra dependencies:

```sh
rustc --edition=2021 -O fuzz/wire_smoke.rs -o /tmp/chicory-wire-smoke
/tmp/chicory-wire-smoke
```

It imports the production codec source and calls the same fuzz entry point with
valid messages, every truncation, single-byte mutations, size boundaries, and
deterministically generated arbitrary data. The regular feature test suite also
contains proptest coverage and golden vectors from Beignet:

```sh
cargo test --features chicory --lib chicory::wire::tests
```

The native `chicory_ffor` target exercises strict signed FFOR frames and the
versioned epoch, used-identity archive and channel-reestablish records. Successful
decodes must roundtrip exactly. Signed frames are verified against a fixed public
key, and decoded epoch transcripts verify their stored node signatures. This
target constructs no node and performs no network, wallet or signing operation.
The parser facade exists only under `cfg(fuzzing)` in the native dependency.

```sh
python3 fuzz/prepare_ffor_corpus.py
cargo +nightly fuzz run chicory_ffor --features native-ffor-fuzz -- -max_len=524288 -max_total_time=60
```

The seed command copies published Appendix D and concurrent-receive wire vectors
and writes empty synthetic archive/reestablish records. It never reads a node
database, live epoch journal, seed or signing key.

Keep `secp256k1_fuzz` unset. That separate flag replaces secp256k1 operations with
test stubs. `cfg(fuzzing)` alone retains real verification in this parser, although
other native subsystems contain fuzz-specific behavior and are outside this
target's scope. Exact signature vectors and the same parser entry are also tested
under the normal compiler configuration:

```sh
cargo test -p lightning --lib ln::ffor::tests
```

The unit smoke corpus covers valid vectors and custody records, truncations,
single-byte mutations and size boundaries. It does not replace an instrumented
fuzz campaign or native channel lifecycle testing.

On 2026-10-25, the instrumented targets completed bounded 120-second campaigns
on nightly Rust 1.101.0 with `cargo-fuzz` 0.13.2 and real secp256k1 verification:

| Target | Executions | Result |
| --- | ---: | --- |
| `chicory_ffor` | 4,118,637 | No crash or invariant failure |
| `chicory_wire` | 321,330 | No crash or invariant failure |

Each run ended after 121 seconds as reported by libFuzzer. These are short smoke
campaigns, not exhaustive verification. Generated corpora, build products and
logs are intentionally excluded from the branch.
