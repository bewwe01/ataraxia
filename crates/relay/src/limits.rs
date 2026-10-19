//! Rate limiting: token buckets keyed by delivery-token hash, mailbox, connection or an
//! in-memory source key (IPv4 address or IPv6 /64; see `server.rs`). Nothing here is logged or
//! stored, and [`KeyedLimiter::prune`] forgets every bucket that has refilled, so a source key
//! is held only while its bucket is in use (PROTOCOL §6.3; review P3R3-4).

use std::collections::HashMap;
use std::time::Instant;

/// A token bucket: `burst` capacity, refilled at `per_sec` tokens per second.
#[derive(Debug, Clone, Copy)]
pub struct Rate {
    pub burst: u32,
    pub per_sec: f64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: Rate, now: Instant) -> Self {
        Self {
            tokens: f64::from(rate.burst),
            last: now,
        }
    }

    fn take(&mut self, rate: Rate, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate.per_sec).min(f64::from(rate.burst));
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A single bucket (per connection).
#[derive(Debug, Clone, Copy)]
pub struct Limiter {
    rate: Rate,
    bucket: Bucket,
}

impl Limiter {
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            bucket: Bucket::new(rate, Instant::now()),
        }
    }

    pub fn allow(&mut self) -> bool {
        self.bucket.take(self.rate, Instant::now())
    }

    /// Whether a token is available now, without taking it.
    pub fn would_allow(&self) -> bool {
        let mut probe = self.bucket;
        probe.take(self.rate, Instant::now())
    }
}

impl Bucket {
    fn is_full(&self, rate: Rate, now: Instant) -> bool {
        let tokens = self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate.per_sec;
        tokens >= f64::from(rate.burst)
    }
}

/// Buckets keyed by a 32-byte value, with a hard cap on how many keys are tracked so the
/// limiter cannot be used to exhaust memory. When full, the stalest keys are evicted.
#[derive(Debug)]
pub struct KeyedLimiter {
    rate: Rate,
    max_keys: usize,
    buckets: HashMap<[u8; 32], Bucket>,
}

impl KeyedLimiter {
    pub fn new(rate: Rate, max_keys: usize) -> Self {
        Self {
            rate,
            max_keys,
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, key: &[u8; 32]) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&mut self, key: &[u8; 32], now: Instant) -> bool {
        if !self.buckets.contains_key(key) && self.buckets.len() >= self.max_keys {
            self.evict(now);
        }
        let rate = self.rate;
        self.buckets
            .entry(*key)
            .or_insert_with(|| Bucket::new(rate, now))
            .take(rate, now)
    }

    /// Whether `key` has a token available now, without taking it.
    pub fn would_allow(&self, key: &[u8; 32]) -> bool {
        self.buckets.get(key).is_none_or(|b| {
            let mut probe = *b;
            probe.take(self.rate, Instant::now())
        })
    }

    /// Gives back a token taken by [`Self::allow`] for a request that was then refused
    /// for another reason (review P3R3-9).
    pub fn refund(&mut self, key: &[u8; 32]) {
        let burst = f64::from(self.rate.burst);
        if let Some(b) = self.buckets.get_mut(key) {
            b.tokens = (b.tokens + 1.0).min(burst);
        }
    }

    /// Forgets every bucket that has refilled to its burst: it is indistinguishable from a
    /// fresh one, so nothing is lost, and keys (source keys included) are not kept longer
    /// than their bucket is in use. Called from the relay's periodic sweep.
    pub fn prune(&mut self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&mut self, now: Instant) {
        let rate = self.rate;
        self.buckets.retain(|_, b| !b.is_full(rate, now));
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Drops full buckets; if none, the oldest half.
    fn evict(&mut self, now: Instant) {
        self.prune_at(now);
        if self.buckets.len() >= self.max_keys {
            let mut ages: Vec<Instant> = self.buckets.values().map(|b| b.last).collect();
            ages.sort_unstable();
            if let Some(cut) = ages.get(ages.len() / 2).copied() {
                self.buckets.retain(|_, b| b.last > cut);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_bursts_then_refills() {
        let rate = Rate {
            burst: 3,
            per_sec: 1.0,
        };
        let mut l = KeyedLimiter::new(rate, 10);
        let t0 = Instant::now();
        let k = [1u8; 32];
        assert!((0..3).all(|_| l.allow_at(&k, t0)));
        assert!(!l.allow_at(&k, t0));
        assert!(l.allow_at(&k, t0 + Duration::from_millis(1100)));
        assert!(!l.allow_at(&k, t0 + Duration::from_millis(1100)));
        // Other keys are independent.
        assert!(l.allow_at(&[2u8; 32], t0));
    }

    /// P3R3-4: refilled buckets, and with them their keys, are forgotten.
    #[test]
    fn prune_forgets_refilled_buckets() {
        let rate = Rate {
            burst: 2,
            per_sec: 1.0,
        };
        let mut l = KeyedLimiter::new(rate, 10);
        let t0 = Instant::now();
        assert!(l.allow_at(&[1u8; 32], t0));
        assert!(l.allow_at(&[2u8; 32], t0));
        assert!(l.allow_at(&[2u8; 32], t0));
        l.prune_at(t0 + Duration::from_millis(1100));
        assert_eq!(
            l.len(),
            1,
            "key 1 refilled and is forgotten; key 2 is still in use"
        );
        l.prune_at(t0 + Duration::from_millis(2100));
        assert!(l.is_empty());
    }

    /// P3R3-9: a refunded token is usable again.
    #[test]
    fn refund_returns_a_token() {
        let rate = Rate {
            burst: 1,
            per_sec: 0.0001,
        };
        let mut l = KeyedLimiter::new(rate, 10);
        let t0 = Instant::now();
        assert!(l.allow_at(&[1u8; 32], t0));
        assert!(!l.allow_at(&[1u8; 32], t0));
        l.refund(&[1u8; 32]);
        assert!(l.allow_at(&[1u8; 32], t0));
    }

    #[test]
    fn key_count_is_bounded() {
        let mut l = KeyedLimiter::new(
            Rate {
                burst: 1,
                per_sec: 0.001,
            },
            100,
        );
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            l.allow_at(&k, t0 + Duration::from_millis(u64::from(i)));
            assert!(l.buckets.len() <= 100);
        }
    }
}
