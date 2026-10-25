#![no_main]

use libfuzzer_sys::fuzz_target;

// cargo-fuzz enables cfg(fuzzing). The separate secp256k1_fuzz flag must remain
// unset so signed-message checks execute real ECDSA verification.
#[cfg(not(fuzzing))]
compile_error!("Use cargo-fuzz or RUSTFLAGS='--cfg fuzzing' for this target");

fuzz_target!(|data: &[u8]| {
	lightning::ln::fuzz_ffor_parsers(data);
});
