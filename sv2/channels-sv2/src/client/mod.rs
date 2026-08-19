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
/// growth. Past jobs exist for late-share validation, so the cap must stay nonzero. On overflow,
/// the oldest past job is evicted: a share against it is rejected as
/// [`InvalidJobId`](crate::client::share_accounting::ShareValidationError::InvalidJobId) even
/// though it would otherwise have been accepted and propagated — a bounded loss of creditable
/// work, the price of bounding memory under a hostile upstream.
///
/// 50 matches the server-side cap, so a proxy's client channel never evicts a job its upstream
/// still accepts, and buys ample headroom over the reachable submit depth of ~1-2 past jobs at a
/// small measured memory cost — see the load-test data in PR #2290.
///
/// This is only the default. The cap is really a retention window — `cap / job rate` — and the
/// job rate belongs to the deployment, so channel constructors take a
/// `max_past_jobs: Option<NonZeroUsize>` and fall back to this value when passed `None`.
pub const MAX_PAST_JOBS: usize = 50;

/// Maximum number of accepted-share hashes a client channel retains for duplicate detection.
///
/// 4 096 hashes is one 128 KB allocation, which keeps the `no_std`/embedded use case viable:
/// the bound has to be affordable on the smallest supported device, since an adversarial
/// upstream advertising a trivial target can drive the cache to it at message speed.
///
/// A client cache does not need to hold a whole chain tip's worth of shares. It exists to catch
/// a share source re-submitting work it already sent — a retransmit or a buggy loop, which
/// arrives within seconds — not to reconcile a tip. 4 096 covers ~11 hours of history for a
/// typical 6 shares/min channel and ~7 minutes for a very busy 600 shares/min proxy channel,
/// far beyond any realistic duplicate window in both cases. Overflow evicts oldest-first, and
/// an evicted-then-replayed hash costs one double-counted local statistic.
pub const MAX_SEEN_SHARES: usize = 4_096;

/// Resolves a caller-supplied past-jobs cap against [`MAX_PAST_JOBS`].
///
/// Keeps the default referenced in one place, so changing it does not mean touching every
/// channel constructor.
pub(crate) fn resolve_max_past_jobs(max_past_jobs: Option<core::num::NonZeroUsize>) -> usize {
    max_past_jobs
        .map(core::num::NonZeroUsize::get)
        .unwrap_or(MAX_PAST_JOBS)
}

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
