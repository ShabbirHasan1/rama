// use crate::layer::custom_proxy_auth::WARNING_MESSAGE;
use crate::{Request, Response};
use ahash::RandomState;
use crossbeam_epoch::{self as epoch, Atomic, Owned};
// use http::StatusCode;
use http::header::USER_AGENT;
use moka::Expiry;
use moka::future::Cache;
use rama_core::Layer;
use rama_core::Service;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt};
use rama_core::extensions::ExtensionsRef as _;
use rama_http_headers::{HeaderMapExt as _, ProxyAuthorization};
// use rama_http_types::body::OptionalBody;
use rama_net::stream::SocketInfo;
use rama_net::user::Basic;
use rama_tcp::TcpStream;
use rama_utils::str::smol_str::ToSmolStr as _;
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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug, Clone)]
pub struct Firewall {
    pub bans: Cache<Arc<str>, BanInfo, RandomState>,
    pub bloom: Arc<AtomicBloom>,
    pub bloom_refresh_interval: Duration,
    pub last_bloom_refresh: Arc<AtomicU64>,
    pub max_entries: u64,
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new(100_000)
    }
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
    pub async fn is_banned(&self, key: &str) -> Option<BanInfo> {
        let potential_match = {
            let guard = epoch::pin();
            self.bloom.get(&guard).contains(key)
        };

        if !potential_match {
            rama_core::telemetry::tracing::trace!(subject = %key, "Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT is NOT Banned");
            return None;
        }

        if let Some(ban_info) = self.bans.get(key).await {
            rama_core::telemetry::tracing::trace!(subject = %key, ban_info = ?ban_info, ban_time = ?ban_info.calculate_ttl(), "Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT is Banned");
            Some(ban_info)
        } else {
            rama_core::telemetry::tracing::trace!(subject = %key, "Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT is NOT Banned");
            None
        }
    }

    pub async fn record_violation(&self, key: &str) -> Option<BanInfo> {
        let ban_infos: Option<BanInfo>;
        rama_core::telemetry::tracing::trace!(subject = %key, "Banning Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
        if let Some(mut info) = self.bans.get(key).await {
            info.increment();
            self.bans.insert(Arc::from(key), info).await;
            ban_infos = Some(info);
            rama_core::telemetry::tracing::info!(subject = %key, ban_info = ?info, ban_time = ?info.calculate_ttl(), "Successfully Banned Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
        } else {
            let ban_info = BanInfo::new();
            self.bans.insert(Arc::from(key), ban_info).await;
            // self.bloom.get().insert(key);

            // Pin the epoch to insert into the current bloom
            let guard = epoch::pin();
            self.bloom.get(&guard).insert(key);
            drop(guard);
            ban_infos = Some(ban_info);
            rama_core::telemetry::tracing::info!(subject = %key, ban_info = ?ban_info, ban_time = ?ban_info.calculate_ttl(), "Successfully Banned Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
        }

        self.maybe_refresh_bloom();
        rama_core::telemetry::tracing::trace!(subject = %key, "Successfully Banned Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
        ban_infos
    }

    pub fn maybe_refresh_bloom(&self) {
        rama_core::telemetry::tracing::trace!("Initiated Maybe Refreshing Bloom Filter");
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
        rama_core::telemetry::tracing::trace!("Finished Maybe Refreshing Bloom Filter");
    }

    #[inline]
    pub async fn unban(&self, key: &str) {
        rama_core::telemetry::tracing::trace!(subject = %key, "Unbanning Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
        self.bans.invalidate(key).await;
        rama_core::telemetry::tracing::info!(subject = %key, "Successfully Unbanned Subjected IPv4/IPv6 ADDRESS or API_KEY or USER_NAME or USER_AGENT");
    }

    #[inline]
    pub fn stats(&self) -> (u64, u64) {
        (self.bans.entry_count(), self.bans.weighted_size())
    }

    pub async fn refresh_bloom(&self) {
        rama_core::telemetry::tracing::trace!("Initiated Refreshing Bloom Filter");
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
        rama_core::telemetry::tracing::trace!("Finished Refreshing Bloom Filter");
    }
}

// rama_utils::macros::impl_deref!(Firewall);

#[derive(Debug, Clone)]
pub struct FirewallLayer {
    pub firewall: Arc<Firewall>,
}

impl FirewallLayer {
    pub fn new(firewall: Arc<Firewall>) -> Self {
        Self { firewall }
    }
}

#[derive(Clone)]
pub struct FirewallService<S> {
    inner: S,
    firewall: Arc<Firewall>,
}

impl<S> Layer<S> for FirewallLayer {
    type Service = FirewallService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FirewallService {
            inner,
            firewall: self.firewall.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        FirewallService {
            inner,
            firewall: self.firewall,
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for FirewallService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirewallService")
            .field("firewall", &self.firewall)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> Service<TcpStream> for FirewallService<S>
where
    S: Service<TcpStream, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: TcpStream) -> Result<Self::Output, Self::Error> {
        let ip_addr = stream
            .extensions()
            .get::<SocketInfo>()
            .context("no socket info found")?
            .peer_addr()
            .ip_addr
            .to_smolstr();

        if let Some(_is_banned) = self.firewall.is_banned(&ip_addr).await {
            rama_core::telemetry::tracing::warn!(ip_addr = %ip_addr, "dropping connection for blocked IP Address" );
            return Err(
                BoxError::from("drop connection for blocked ip").context_field("ip_addr", ip_addr)
            );
        }
        self.inner.serve(stream).await.into_box_error()
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for FirewallService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let ip_addr = req
            .extensions()
            .get::<SocketInfo>()
            .context("no socket info found")?
            .peer_addr()
            .ip_addr
            .to_smolstr();

        let user_agent = req
            .headers()
            .get(USER_AGENT)
            .context("no user_agent info found in headers")?
            .to_str()
            .context("user_agent is not valid UTF-8")?
            .to_owned();

        let api_key = req
            .headers()
            .typed_get::<ProxyAuthorization<Basic>>()
            .map(|h| h.0)
            .or_else(|| req.extensions().get::<Basic>().cloned())
            .context("failed to extract proxy authorization header value and Basic credentials")?
            .username()
            .to_owned();

        let is_ip_banned = self.firewall.is_banned(&ip_addr).await;
        let is_ua_banned = self.firewall.is_banned(&user_agent).await;
        let is_un_banned = self.firewall.is_banned(&api_key).await;

        if let Some(_ip_ban_info) = is_ip_banned {
            rama_core::telemetry::tracing::warn!(
                ip_addr = %ip_addr,
                "dropping connection for blocked IP Address"
            );
            return Err(BoxError::from("drop connection for blocked ip address")
                .context_field("ip_addr", ip_addr));
            // return Response::builder()
            //     .status(StatusCode::FORBIDDEN)
            //     .header(http::header::WARNING, WARNING_MESSAGE)
            //     .body(ResBody::from("hello"))
            //     .context("drop connection for blocked ip address")
            //     .context_field("ip_addr", ip_addr);
        }

        if let Some(_un_ban_info) = is_un_banned {
            rama_core::telemetry::tracing::warn!(
                api_key = %api_key,
                "dropping connection for blocked API_KEY",
            );
            return Err(BoxError::from("drop connection for blocked api_key")
                .context_field("api_key", api_key));
            // return Response::builder()
            //     .status(StatusCode::FORBIDDEN)
            //     .header(http::header::WARNING, WARNING_MESSAGE)
            //     .body(rama_http_types::Body::empty())
            //     .context("drop connection for blocked api_key")
            //     .context_field("api_key", api_key);
        }

        if let Some(_ua_ban_info) = is_ua_banned {
            rama_core::telemetry::tracing::warn!(
                user_agent = %user_agent,
                "dropping connection for blocked User Agent",
            );
            return Err(BoxError::from("drop connection for blocked user agent")
                .context_field("user_agent", user_agent));
            // return Response::builder()
            //     .status(StatusCode::FORBIDDEN)
            //     .header(http::header::WARNING, WARNING_MESSAGE)
            //     .body(())
            //     .context("drop connection for blocked user agent")
            //     .context_field("user_agent", user_agent);
        }

        self.inner.serve(req).await.into_box_error()
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
