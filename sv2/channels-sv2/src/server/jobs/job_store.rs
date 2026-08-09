//! Internal job storage and lifecycle management for server-side SV2 channels.
//!
//! ## Responsibilities
//!
//! - **Job Storage**: Manages collections of jobs indexed by job ID and template ID.
//! - **Job Activation**: Handles transitions between future, active, past, and stale jobs.
//! - **Template Mapping**: Tracks mappings from template IDs to job IDs for future jobs.
//! - **Lifecycle Management**: Ensures correct state transitions when activating jobs or updating
//!   chain tips.
//! - **Retired Extranonce Prefixes**: Holds on to extranonce prefixes that were rotated out of the
//!   channel while jobs created under them can still accept shares, so that their allocator slots
//!   are not handed to another channel too early.
use std::collections::{HashMap, VecDeque};

use super::Job;
use crate::extranonce_manager::ExtranoncePrefix;

/// Maximum number of future jobs a server channel retains while waiting for a
/// template-distribution `SetNewPrevHash`.
///
/// Template Distribution peers control `template_id`, so future jobs are stored under a
/// peer-controlled key. Bounding the map prevents a malicious or buggy peer from exhausting
/// server memory by streaming future templates while withholding `SetNewPrevHash`. On overflow,
/// the oldest future job is evicted.
pub(crate) const MAX_FUTURE_JOBS: usize = 16;

/// Maximum number of past jobs a server channel retains under the current chain tip.
///
/// Past jobs exist for late-share validation, so the cap must stay nonzero; shares against an
/// evicted job degrade to `InvalidJobId`, acceptable within a single tip window. Bounding the map
/// prevents a malicious template-distribution peer from exhausting server memory by streaming
/// non-future templates while withholding `SetNewPrevHash`.
///
/// 50 buys ample headroom over the reachable submit depth (a miner abandons a job once the next
/// one arrives, so late shares realistically target the last 1-2 jobs) at a small measured
/// memory cost — see the load-test data in PR #2290.
pub(crate) const MAX_PAST_JOBS: usize = 50;

/// Internal implementation for tracking mining job states in SV2 server channels.
///
/// Maintains collections for future, active, past, and stale jobs, and tracks template-to-job ID
/// mappings for future job activation.
#[derive(Debug)]
pub(crate) struct JobStore<T: Job> {
    future_template_to_job_id: HashMap<u64, u32>,
    // Future template IDs ordered by receipt, oldest at the front and newest at the back.
    // Replaced IDs move to the back; overflow evicts from the front.
    future_template_order: VecDeque<u64>,
    // Future jobs are indexed with job_id (u32)
    future_jobs: HashMap<u32, T>,
    active_job: Option<T>,
    // Past jobs are indexed with job_id (u32)
    past_jobs: HashMap<u32, T>,
    // Past job IDs ordered by retirement, oldest at the front and newest at the back.
    // Replaced IDs move to the back; overflow evicts from the front.
    past_job_order: VecDeque<u32>,
    // Stale jobs are indexed with job_id (u32)
    stale_jobs: HashMap<u32, T>,
    // Extranonce prefixes rotated out of the channel that are still referenced by at least one job
    // that can accept shares. Holding the object here keeps its allocator slot reserved; dropping
    // it releases the slot.
    retired_extranonce_prefixes: Vec<ExtranoncePrefix>,
}

impl<T: Job> JobStore<T> {
    /// Creates a new empty job store.
    pub fn new() -> Self {
        Self {
            future_template_to_job_id: HashMap::new(),
            future_template_order: VecDeque::new(),
            future_jobs: HashMap::new(),
            active_job: None,
            past_jobs: HashMap::new(),
            past_job_order: VecDeque::new(),
            stale_jobs: HashMap::new(),
            retired_extranonce_prefixes: Vec::new(),
        }
    }
}

impl<T: Job> Default for JobStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Job> JobStore<T> {
    /// Adds a future job associated with a template ID.
    ///
    /// If the template ID was already mapped to a future job, that job is dropped, since it could
    /// never be activated again (activation resolves jobs through this mapping).
    ///
    /// At most `MAX_FUTURE_JOBS` future jobs are kept: storing a new one beyond that limit evicts
    /// the oldest, since template IDs are peer-controlled and must not grow memory unboundedly.
    ///
    /// Returns the new job's ID.
    pub fn add_future_job(&mut self, template_id: u64, new_job: T) -> u32 {
        let new_job_id = new_job.get_job_id();
        if let Some(old_job_id) = self
            .future_template_to_job_id
            .insert(template_id, new_job_id)
        {
            self.future_jobs.remove(&old_job_id);
        }
        self.future_jobs.insert(new_job_id, new_job);

        // a replaced template_id moves to the back of the eviction order
        self.future_template_order.retain(|id| *id != template_id);
        self.future_template_order.push_back(template_id);

        if self.future_jobs.len() > MAX_FUTURE_JOBS {
            if let Some(evicted_template_id) = self.future_template_order.pop_front() {
                if let Some(evicted_job_id) =
                    self.future_template_to_job_id.remove(&evicted_template_id)
                {
                    self.future_jobs.remove(&evicted_job_id);
                }
            }
        }

        new_job_id
    }

    /// Moves the active job (if any) into past jobs, evicting the oldest past job beyond
    /// `MAX_PAST_JOBS`. A share against an evicted job degrades to `InvalidJobId` instead of
    /// `Stale`, acceptable within a single tip window.
    fn retire_active_to_past(&mut self) {
        if let Some(active_job) = self.active_job.take() {
            let job_id = active_job.get_job_id();
            self.past_jobs.insert(job_id, active_job);

            // a replaced job_id moves to the back of the eviction order
            self.past_job_order.retain(|id| *id != job_id);
            self.past_job_order.push_back(job_id);

            if self.past_jobs.len() > MAX_PAST_JOBS {
                if let Some(evicted_job_id) = self.past_job_order.pop_front() {
                    self.past_jobs.remove(&evicted_job_id);
                }
            }
        }
    }

    /// Adds an active job, moving the previous active job (if any) to past jobs.
    ///
    /// At most `MAX_PAST_JOBS` past jobs are kept: retiring one beyond that limit evicts the
    /// oldest.
    pub fn add_active_job(&mut self, job: T) {
        // Move currently active job to past jobs (so it can be marked as stale)
        self.retire_active_to_past();
        // Set the new active job
        self.active_job = Some(job);
    }

    /// Replaces the active job, dropping the previous active job (if any).
    ///
    /// For channels that never validate shares (group channels), where retaining the replaced
    /// job would be pure memory growth under peer-controlled message streams.
    pub fn replace_active_job(&mut self, job: T) {
        self.active_job = Some(job);
    }

    /// Activates a future job given by template ID and header timestamp, dropping the previously
    /// active job (if any) instead of retiring it to past jobs.
    /// Returns `true` if successful, `false` if not found.
    ///
    /// For channels that never validate shares (group channels), which keep no past or stale
    /// job history.
    pub fn activate_future_job_replacing_active(
        &mut self,
        template_id: u64,
        prev_hash_header_timestamp: u32,
    ) -> bool {
        // the active job is only dropped once activation is known to succeed, so that a failed
        // activation does not corrupt channel state
        let activatable = self
            .future_template_to_job_id
            .get(&template_id)
            .is_some_and(|job_id| self.future_jobs.contains_key(job_id));
        if !activatable {
            return false;
        }

        // with no active job left to retire, the activation below leaves past and stale jobs
        // empty
        self.active_job = None;
        self.activate_future_job(template_id, prev_hash_header_timestamp)
    }

    /// Activates a future job given by template ID and header timestamp.
    /// Returns `true` if successful, `false` if not found.
    pub fn activate_future_job(
        &mut self,
        template_id: u64,
        prev_hash_header_timestamp: u32,
    ) -> bool {
        let mut future_job =
            if let Some(job_id) = self.future_template_to_job_id.remove(&template_id) {
                if let Some(job) = self.future_jobs.remove(&job_id) {
                    job
                } else {
                    return false;
                }
            } else {
                return false;
            };

        // Move currently active job to past jobs (so it can be marked as stale)
        self.retire_active_to_past();

        // Activate the future job
        future_job.activate(prev_hash_header_timestamp);
        self.active_job = Some(future_job);
        self.future_jobs.clear();
        self.future_template_to_job_id.clear();
        self.future_template_order.clear();

        self.mark_past_jobs_as_stale();

        true
    }

    /// Moves the active job (if any) into past jobs.
    ///
    /// At most `MAX_PAST_JOBS` past jobs are kept: retiring one beyond that limit evicts the
    /// oldest.
    pub fn deactivate_job(&mut self) {
        self.retire_active_to_past();
    }

    /// Marks all past jobs as stale so shares can be rejected with the proper error code.
    pub fn mark_past_jobs_as_stale(&mut self) {
        // Transfer past jobs to stale jobs collection and reset past jobs to empty
        self.stale_jobs = std::mem::take(&mut self.past_jobs);
        self.past_job_order.clear();
        // jobs that just went stale can no longer accept shares, so any retired extranonce prefix
        // they were the last reference to is now releasable
        self.prune_retired_extranonce_prefixes();
    }

    /// Takes ownership of an extranonce prefix that is no longer the channel's current one,
    /// releasing it only once no job created under it can accept shares anymore.
    ///
    /// Jobs only carry a copy of the extranonce prefix bytes they were created under, and stay
    /// valid across a prefix rotation. Dropping the prefix object right away would return its
    /// slot to the allocator while those jobs still validate shares under those bytes, allowing
    /// the same extranonce space to be handed to a second live channel.
    pub fn retire_extranonce_prefix(&mut self, extranonce_prefix: ExtranoncePrefix) {
        if self.is_extranonce_prefix_in_use(extranonce_prefix.as_bytes()) {
            self.retired_extranonce_prefixes.push(extranonce_prefix);
        }
        // otherwise it drops here, releasing its slot right away
    }

    /// Drops every retired extranonce prefix that no future, active or past job still references.
    /// Dropping releases the prefix's slot back to its allocator.
    ///
    /// Stale jobs are deliberately not consulted: shares against them are rejected as stale, so
    /// they can no longer be credited under the old prefix bytes.
    fn prune_retired_extranonce_prefixes(&mut self) {
        // bind the job collections separately, so that the closure borrows them instead of
        // borrowing all of `self` (which `retain` needs mutably)
        let future_jobs = &self.future_jobs;
        let active_job = &self.active_job;
        let past_jobs = &self.past_jobs;

        self.retired_extranonce_prefixes.retain(|prefix| {
            future_jobs
                .values()
                .chain(active_job.iter())
                .chain(past_jobs.values())
                .any(|job| job.get_extranonce_prefix() == prefix.as_bytes())
        });
    }

    /// Whether any future, active or past job was created under `extranonce_prefix`.
    fn is_extranonce_prefix_in_use(&self, extranonce_prefix: &[u8]) -> bool {
        self.future_jobs
            .values()
            .chain(self.active_job.iter())
            .chain(self.past_jobs.values())
            .any(|job| job.get_extranonce_prefix() == extranonce_prefix)
    }

    /// Returns the job ID for a future job from a template ID, if any.
    pub fn get_future_job_id_from_template_id(&self, template_id: u64) -> Option<u32> {
        self.future_template_to_job_id.get(&template_id).cloned()
    }

    /// Returns a reference to the currently active job, if any.
    pub fn get_active_job(&self) -> Option<&T> {
        self.active_job.as_ref()
    }

    /// Returns true if there are any future jobs, false otherwise.
    pub fn has_future_jobs(&self) -> bool {
        !self.future_jobs.is_empty()
    }

    /// Returns a reference to a future job from its job ID, if any.
    pub fn get_future_job(&self, job_id: u32) -> Option<&T> {
        self.future_jobs.get(&job_id)
    }

    /// Returns a reference to a past job from its job ID, if any.
    pub fn get_past_job(&self, job_id: u32) -> Option<&T> {
        self.past_jobs.get(&job_id)
    }

    /// Returns a reference to a stale job from its job ID, if any.
    pub fn get_stale_job(&self, job_id: u32) -> Option<&T> {
        self.stale_jobs.get(&job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyJob {
        job_id: u32,
    }

    impl Job for DummyJob {
        fn get_job_id(&self) -> u32 {
            self.job_id
        }

        fn get_extranonce_prefix(&self) -> &[u8] {
            &[]
        }

        fn activate(&mut self, _prev_hash_header_timestamp: u32) {}
    }

    #[test]
    fn future_jobs_are_bounded() {
        let mut store = JobStore::new();

        let flood_size = 10_000u64;
        for template_id in 0..flood_size {
            store.add_future_job(
                template_id,
                DummyJob {
                    job_id: template_id as u32,
                },
            );
        }

        // only the newest MAX_FUTURE_JOBS survive; the oldest were evicted
        for template_id in 0..flood_size - MAX_FUTURE_JOBS as u64 {
            assert!(store
                .get_future_job_id_from_template_id(template_id)
                .is_none());
            assert!(store.get_future_job(template_id as u32).is_none());
        }
        for template_id in flood_size - MAX_FUTURE_JOBS as u64..flood_size {
            assert!(store
                .get_future_job_id_from_template_id(template_id)
                .is_some());
            assert!(store.get_future_job(template_id as u32).is_some());
        }
    }

    #[test]
    fn past_jobs_are_bounded() {
        let mut store = JobStore::new();

        let flood_size = 10_000u32;
        for job_id in 0..flood_size {
            store.add_active_job(DummyJob { job_id });
        }

        // the last job is active; of the retired ones, only the newest MAX_PAST_JOBS survive
        for job_id in 0..flood_size - 1 - MAX_PAST_JOBS as u32 {
            assert!(store.get_past_job(job_id).is_none());
        }
        for job_id in flood_size - 1 - MAX_PAST_JOBS as u32..flood_size - 1 {
            assert!(store.get_past_job(job_id).is_some());
        }
        assert_eq!(
            store.get_active_job().map(|job| job.get_job_id()),
            Some(flood_size - 1)
        );
    }

    #[test]
    fn reused_template_id_evicts_superseded_future_job() {
        let mut store = JobStore::new();

        let old_job_id = store.add_future_job(1, DummyJob { job_id: 10 });
        let new_job_id = store.add_future_job(1, DummyJob { job_id: 11 });

        // the superseded job could never be activated again, so it must not be retained
        assert!(store.get_future_job(old_job_id).is_none());
        assert!(store.get_future_job(new_job_id).is_some());
        assert_eq!(
            store.get_future_job_id_from_template_id(1),
            Some(new_job_id)
        );
    }
}
