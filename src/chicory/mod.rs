//! Experimental native interoperability with the protocols used by Chicory.
//!
//! Compatibility is pinned to the installed phone versions and qualified paths
//! documented below. Enabling the Cargo feature
//! alone does not advertise FFOR support; the separate offline policy must be
//! enabled and the native signer must support it. Direct funding requires the
//! explicitly enabled native v2, relay and stable funding-key policies.
//! See `docs/chicory-primary.md` for the implementation and qualification status.
//!
//! The service refuses new registrations until explicitly enabled:
//!
//! ```
//! use ldk_node::chicory::JitServiceConfig;
//! let policy = JitServiceConfig::default();
//! assert!(!policy.enabled);
//! assert!(policy.validate().is_ok());
//! ```

#![forbid(unsafe_code)]

pub mod conflict;
mod conflict_service;
mod offline;
mod peer_storage;
mod service;
pub mod wire;

/// Native offline receive admission limits. Disabled by default; existing
/// durable obligations remain recoverable when admission is disabled.
pub use lightning::ln::channelmanager::FforPolicy as OfflineReceiveConfig;
pub(crate) use peer_storage::PeerStorageChannelHandler;
pub(crate) use service::ChicoryService;
pub use service::{JitConfigError, JitServiceConfig};
