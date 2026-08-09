//! Sv2 channels - Mining Clients Abstractions.
//!
//! The `client` module is compatible with `no_std` environments. To enable this mode, build the
//! crate with the `no_std` feature. In this configuration, standard library collections are
//! replaced with the `hashbrown` crate, together with `core` and `alloc`, allowing the module to be
//! used in embedded or constrained contexts.

pub mod error;
pub mod extended;
pub mod group;
pub mod share_accounting;
pub mod standard;

/// Maximum number of future jobs a client channel retains while waiting for a
/// [`SetNewPrevHash`](mining_sv2::SetNewPrevHash) (or chain tip update).
///
/// Upstream servers control `job_id`, so future jobs are stored under an upstream-controlled key.
/// Bounding this map prevents a malicious or buggy server from exhausting client memory by
/// streaming future jobs while withholding [`SetNewPrevHash`](mining_sv2::SetNewPrevHash). On
/// overflow, the oldest future job is evicted.
pub const MAX_FUTURE_JOBS: usize = 16;

/// Maximum number of past jobs a client channel retains under the current chain tip.
///
/// Upstream servers control the job stream, so a malicious or buggy server can force one retained
/// past job per immediately-active job message. Bounding this map prevents unbounded memory
/// growth. Past jobs exist for late-share validation, so the cap must stay nonzero; shares
/// against an evicted job degrade to
/// [`InvalidJobId`](crate::client::share_accounting::ShareValidationError::InvalidJobId) within a
/// single tip window. On overflow, the oldest past job is evicted.
///
/// 50 matches the server-side cap, so a proxy's client channel never evicts a job its upstream
/// still accepts, and buys ample headroom over the reachable submit depth of ~1-2 past jobs at a
/// small measured memory cost — see the load-test data in PR #2290.
pub const MAX_PAST_JOBS: usize = 50;

// Type aliases that switch between `std::collections` and `hashbrown`
// depending on whether the `no_std` feature is enabled.
#[cfg(not(feature = "no_std"))]
type HashMap<K, V> = std::collections::HashMap<K, V>;
#[cfg(not(feature = "no_std"))]
type HashSet<T> = std::collections::HashSet<T>;
#[cfg(feature = "no_std")]
type HashMap<K, V> = hashbrown::HashMap<K, V>;
#[cfg(feature = "no_std")]
type HashSet<T> = hashbrown::HashSet<T>;
