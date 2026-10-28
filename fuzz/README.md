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

On 2026-10-25, the instrumented wire target completed a bounded 120-second campaign
on nightly Rust 1.101.0 with `cargo-fuzz` 0.13.2:

| Target | Executions | Result |
| --- | ---: | --- |
| `chicory_wire` | 321,330 | No crash or invariant failure |

The run ended after 121 seconds as reported by libFuzzer. This is a short smoke
campaign, not exhaustive verification. Generated corpora, build products and
logs are intentionally excluded from the branch.
