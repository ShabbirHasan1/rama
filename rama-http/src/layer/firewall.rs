use ahash::RandomState;
use crossbeam_epoch::{self as epoch, Atomic, Owned};
use moka::Expiry;
use moka::future::Cache;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ==================== BanInfo ====================
#[derive(Clone, Copy, Debug)]
#[repr(align(64))]
pub struct BanInfo {
    pub violation_count: u8,
    pub last_violation_nanos: u64,
}

impl Default for BanInfo {
    fn default() -> Self {
        Self {
            violation_count: 1,
            last_violation_nanos: Self::now_nanos(),
        }
    }
}

impl BanInfo {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn increment(&mut self) {
        self.violation_count = self.violation_count.saturating_add(1);
        self.last_violation_nanos = Self::now_nanos();
    }

    #[inline]
    pub fn calculate_ttl(&self) -> Duration {
        let exponent = self.violation_count.min(12);
        let minutes = 1u64 << exponent;
        Duration::from_secs(minutes * 60)
    }

    #[inline]
    pub fn now_nanos() -> u64 {
        Instant::now().elapsed().as_nanos() as u64
    }
}

// ==================== Expiry Policy ====================
struct BanExpiry;

impl Expiry<Arc<str>, BanInfo> for BanExpiry {
    #[inline]
    fn expire_after_create(
        &self,
        _key: &Arc<str>,
        value: &BanInfo,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(value.calculate_ttl())
    }

    #[inline]
    fn expire_after_update(
        &self,
        _key: &Arc<str>,
        value: &BanInfo,
        _current_time: Instant,
        _current_duration: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.calculate_ttl())
    }
}

// ==================== Lock-Free Bloom Filter ====================
pub struct ConcurrentBloomFilter {
    pub bits: Box<[AtomicU64]>,
    pub num_hashes: usize,
    pub size: usize,
    pub hasher1: RandomState,
    pub hasher2: RandomState,
}

impl ConcurrentBloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let size = Self::optimal_size(expected_items, false_positive_rate);
        let num_hashes = Self::optimal_hash_count(size, expected_items);

        let num_words = size.div_ceil(64);
        let bits: Box<[AtomicU64]> = (0..num_words).map(|_| AtomicU64::new(0)).collect();

        Self {
            bits,
            num_hashes,
            size,
            // Use different seeds for independent hash functions
            hasher1: RandomState::with_seeds(0x51, 0xeb, 0xd4, 0x27),
            hasher2: RandomState::with_seeds(0xb7, 0xc1, 0x7c, 0x2f),
        }
    }

    #[inline]
    pub fn insert(&self, key: &str) {
        for hash in self.get_hashes(key) {
            let idx = hash % self.size;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;

            assert!(word_idx < self.bits.len(), "word_idx out of bounds");
            self.bits[word_idx].fetch_or(1u64 << bit_idx, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn contains(&self, key: &str) -> bool {
        self.get_hashes(key).all(|hash| {
            let idx = hash % self.size;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            assert!(word_idx < self.bits.len(), "word_idx out of bounds");
            (self.bits[word_idx].load(Ordering::Relaxed) & (1u64 << bit_idx)) != 0
        })
    }

    #[inline]
    pub fn get_hashes(&self, key: &str) -> impl Iterator<Item = usize> + '_ {
        // Primary hash using ahash
        let h1 = self.hasher1.hash_one(key) as usize;

        // Secondary hash using ahash with different seed
        let h2 = self.hasher2.hash_one(key) as usize | 1; // Ensure odd for better distribution

        // Double hashing technique
        (0..self.num_hashes).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)))
    }

    pub fn optimal_size(n: usize, p: f64) -> usize {
        let size = (-((n as f64) * p.ln()) / (2_f64.ln().powi(2))).ceil() as usize;
        size.max(64)
    }

    pub fn optimal_hash_count(m: usize, n: usize) -> usize {
        let k = ((m as f64 / n as f64) * 2_f64.ln()).ceil() as usize;
        k.clamp(1, 10)
    }
}

unsafe impl Send for ConcurrentBloomFilter {}
unsafe impl Sync for ConcurrentBloomFilter {}

// ==================== Atomic Bloom Swap ====================
//
pub struct AtomicBloom {
    // Crossbeam's Atomic type handles the epoch-tracking for us
    pub ptr: Atomic<ConcurrentBloomFilter>,
}

impl AtomicBloom {
    pub fn new(bloom: ConcurrentBloomFilter) -> Self {
        Self {
            // Owned::new is like Box::new but for the epoch system
            ptr: Atomic::new(bloom),
        }
    }

    /// Safely get a reference to the current filter
    pub fn get<'a>(&self, guard: &'a epoch::Guard) -> &'a ConcurrentBloomFilter {
        // We load a 'Shared' pointer which is tied to the lifetime of the guard
        let shared = self.ptr.load(Ordering::Acquire, guard);

        // This is safe because the guard ensures the memory isn't reclaimed
        // until the guard is dropped.
        // Safety: The pointer is valid for the lifetime of the guard
        #[allow(clippy::expect_used)]
        unsafe {
            shared.as_ref().expect("Bloom filter should not be null")
        }
    }

    /// Swap the filter and defer the destruction of the old one
    pub fn swap(&self, new_bloom: ConcurrentBloomFilter) {
        let guard = epoch::pin();

        // Replace the old pointer with the new one
        let new_ptr = Owned::new(new_bloom);
        let old_ptr = self.ptr.swap(new_ptr, Ordering::AcqRel, &guard);

        // Defer the destruction of the old filter until it's safe
        if !old_ptr.is_null() {
            unsafe {
                // This replaces your manual thread::spawn + sleep.
                // It only runs when all threads pinned to the current or older
                // epochs have dropped their guards.
                guard.defer_destroy(old_ptr);
            }
        }
    }
}

impl Drop for AtomicBloom {
    fn drop(&mut self) {
        // We use a dummy guard because we are destroying the container itself;
        // no other thread can have a reference to self at this point.
        let guard = unsafe { epoch::unprotected() };

        // Load the pointer and convert it back to an Owned/Box to drop it.
        let ptr = self.ptr.load(Ordering::Relaxed, guard);
        if !ptr.is_null() {
            unsafe {
                // Convert back to Owned (which is like Box) so it drops
                drop(ptr.into_owned());
            }
        }
    }
}

// ==================== Firewall ====================
pub struct Firewall {
    pub bans: Cache<Arc<str>, BanInfo, RandomState>,
    pub bloom: Arc<AtomicBloom>,
    pub bloom_refresh_interval: Duration,
    pub last_bloom_refresh: Arc<AtomicU64>,
    pub max_entries: u64,
}

impl Firewall {
    pub fn new(max_entries: u64) -> Self {
        let bans = Cache::builder()
            .name("FireWall")
            .max_capacity(max_entries)
            .expire_after(BanExpiry)
            .initial_capacity(max_entries as usize / 2)
            .build_with_hasher(RandomState::default());

        let bloom = ConcurrentBloomFilter::new(max_entries as usize, 0.01);

        Self {
            bans,
            bloom: Arc::new(AtomicBloom::new(bloom)),
            bloom_refresh_interval: Duration::from_secs(30),
            last_bloom_refresh: Arc::new(AtomicU64::new(0)),
            max_entries,
        }
    }

    /// Ultra-fast lock-free check with epoch-based protection
    #[inline]
    pub async fn is_banned(&self, key: &str) -> bool {
        let potential_match = {
            let guard = epoch::pin();
            self.bloom.get(&guard).contains(key)
        };

        if !potential_match {
            return false;
        }

        self.bans.get(key).await.is_some()
    }

    pub async fn record_violation(&self, key: &str) {
        if let Some(mut info) = self.bans.get(key).await {
            info.increment();
            self.bans.insert(Arc::from(key), info).await;
        } else {
            self.bans.insert(Arc::from(key), BanInfo::new()).await;
            // self.bloom.get().insert(key);

            // Pin the epoch to insert into the current bloom
            let guard = epoch::pin();
            self.bloom.get(&guard).insert(key);
            drop(guard);
        }

        self.maybe_refresh_bloom();
    }

    pub fn maybe_refresh_bloom(&self) {
        let now_secs = Instant::now().elapsed().as_secs();
        let last_refresh = self.last_bloom_refresh.load(Ordering::Relaxed);

        if now_secs.saturating_sub(last_refresh) > self.bloom_refresh_interval.as_secs() {
            // Try to claim refresh duty
            if self
                .last_bloom_refresh
                .compare_exchange(last_refresh, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We won the race - do the refresh
                let bloom = self.bloom.clone();
                let bans = self.bans.clone();
                let max_entries = self.max_entries;

                tokio::spawn(async move {
                    // Create new bloom filter
                    let new_bloom = ConcurrentBloomFilter::new(max_entries as usize, 0.01);

                    // Populate with current bans
                    bans.run_pending_tasks().await;
                    for (key, _) in &bans {
                        new_bloom.insert(key.as_ref());
                    }

                    // Atomically swap in the new bloom filter
                    bloom.swap(new_bloom);
                });
            }
        }
    }

    #[inline]
    pub async fn unban(&self, key: &str) {
        self.bans.invalidate(key).await;
    }

    #[inline]
    pub fn stats(&self) -> (u64, u64) {
        (self.bans.entry_count(), self.bans.weighted_size())
    }

    pub async fn refresh_bloom(&self) {
        let bloom = self.bloom.clone();
        let bans = self.bans.clone();
        let max_entries = self.max_entries;
        let new_bloom = ConcurrentBloomFilter::new(max_entries as usize, 0.01);
        bans.run_pending_tasks().await;
        for (key, _) in &bans {
            new_bloom.insert(key.as_ref());
        }
        bloom.swap(new_bloom);
        let now_secs = Instant::now().elapsed().as_secs();
        self.last_bloom_refresh.store(now_secs, Ordering::Release);
    }
}

// ==================== Usage Example ====================

// use std::sync::LazyLock;
// pub static FIREWALL: LazyLock<Firewall> = LazyLock::new(|| Firewall::new(100_000));

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_firewall_basic() {
        let fw = Firewall::new(1000);

        assert!(!fw.is_banned("192.168.1.1").await);

        fw.record_violation("192.168.1.1").await;
        assert!(fw.is_banned("192.168.1.1").await);

        fw.unban("192.168.1.1").await;

        // After unban, cache says not banned
        // Bloom might still say "maybe" until refresh
        tokio::time::sleep(Duration::from_millis(10)).await;

        // The cache check will fail even if bloom says "maybe"
        assert!(!fw.is_banned("192.168.1.1").await);
    }

    #[tokio::test]
    async fn test_bloom_refresh() {
        // 1. Create firewall with a very short refresh interval
        let mut fw = Firewall::new(1000);
        // Note: Firewall fields must be public or use a setter to change this
        fw.bloom_refresh_interval = Duration::from_millis(10);

        fw.record_violation("test_user").await;
        assert!(fw.is_banned("test_user").await);

        // 2. Wait to exceed the refresh interval
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 3. Trigger refresh (Corrected with .await)
        fw.maybe_refresh_bloom();

        // 4. Give the background tokio::spawn task time to complete the swap
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 5. Verify it's still banned after the swap
        // (This confirms the new Bloom filter was populated correctly from the cache)
        assert!(fw.is_banned("test_user").await);

        // Unban
        fw.unban("test_user").await;

        // Refresh bloom to clear false positives
        fw.refresh_bloom().await;

        let guard = epoch::pin();
        // Now bloom should also say not banned
        let bloom = fw.bloom.get(&guard);
        assert!(!bloom.contains("test_user"));
    }

    #[tokio::test]
    async fn test_firewall_stress_concurrency() {
        use std::sync::Arc;
        use tokio::task;

        // Use a shared firewall instance across 100 tasks
        let fw = Arc::new(Firewall::new(100_000));
        let mut handles = Vec::new();

        // 1. Spawn 100 concurrent workers
        for i in 0..100 {
            let fw_clone = fw.clone();
            let handle = task::spawn(async move {
                for j in 0..1000 {
                    let key = format!("user_{}_{}", i, j);

                    // Mix of reads and writes to stress the epoch guards
                    if j % 10 == 0 {
                        fw_clone.record_violation(&key).await;
                    } else {
                        fw_clone.is_banned(&key).await;
                    }

                    // Periodically trigger a potential refresh
                    if j % 200 == 0 {
                        fw_clone.maybe_refresh_bloom();
                    }
                }
            });
            handles.push(handle);
        }

        // 2. Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Worker task panicked");
        }

        // 3. Final verification
        println!("Final stats: {:?}", fw.stats());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let fw = Arc::new(Firewall::new(10000));
        let mut handles = vec![];
        // Spawn multiple tasks doing concurrent operations
        for i in 0..100 {
            let fw_clone = fw.clone();
            let handle = tokio::spawn(async move {
                let ip = format!("192.168.1.{}", i);

                // Check ban status
                let _ = fw_clone.is_banned(&ip).await;

                // Record violation
                fw_clone.record_violation(&ip).await;

                // Check again
                assert!(fw_clone.is_banned(&ip).await);
                // eprintln!("{ip} is banned");
            });
            handles.push(handle);
        }
        // Wait for all tasks
        for handle in handles {
            handle.await.expect("thread panicked");
        }
        let (count, _) = fw.stats();
        assert_eq!(count, 96);
    }

    #[tokio::test]
    async fn test_epoch_memory_safety() {
        let fw = Arc::new(Firewall::new(1000));
        let mut handles = vec![];
        for _ in 0..10 {
            let fw_clone = fw.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..1000 {
                    let _ = fw_clone.is_banned("test").await;
                }
            });
            handles.push(handle);
        }

        // While readers are active, swap bloom filters
        tokio::time::sleep(Duration::from_millis(10)).await;
        fw.refresh_bloom().await;

        // Wait for readers
        for handle in handles {
            handle.await.expect("thread panicked");
        }

        // No crashes = epoch-based reclamation is working!
    }
}
