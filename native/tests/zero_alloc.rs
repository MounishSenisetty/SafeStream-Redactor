//! The scanning hot path performs no heap allocation.
//!
//! A counting global allocator wraps the system one. After a warm-up call (which
//! may allocate once: compiled regexes, regex scratch caches, the
//! disagreeing-class table), scanning another window into a buffer with enough
//! capacity must allocate nothing. This file is its own test binary with a single
//! test, so no other thread allocates while it counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use safestream_native::{
    compound_secrets, detect_into, entropy_secrets, CompoundParams, Detection, EntropyParams,
    Summation,
};

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn window(seed: usize, unicode: bool) -> String {
    let mut s = String::new();
    for i in 0..200 {
        s.push_str(match (i + seed) % 9 {
            0 => "mail jane.doe@corp.example.co now ",
            1 => "card 4111 1111 1111 1111 charged ",
            2 => "call +1 (415) 555-2671 or 555 123 4567 ",
            3 => "ssn 123-45-6789 host 10.20.30.40 addr 2001:db8::1 ",
            4 => "key AKIAIOSFODNN7EXAMPLE tok ghp_abcdefghijklmnopqrstuvwxyz0123456789 ",
            5 => "blob AbCdEfGh1234567890IjKlMnOpQrStUvWx pw devPass_pP0p18yO3n!vT8wZ ",
            6 => "2024-01-05T00:00:03Z INFO req 3bd3 latency 42ms status 200 ",
            7 => {
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY----- "
            }
            _ => "plain prose with no secrets in it at all ",
        });
        if unicode {
            // characters on which Rust and Python agree: no shadow copy needed
            s.push_str("naïve 文字 Привет ٩٩ ");
        }
    }
    s
}

#[test]
fn scanning_a_window_does_not_allocate() {
    let ent = EntropyParams::default();
    let comp = CompoundParams::default();
    for unicode in [false, true] {
        let warm = window(0, unicode);
        let hot = window(4, unicode);

        let mut dets: Vec<Detection> = Vec::with_capacity(4096);
        let mut spans: Vec<(usize, usize, f64)> = Vec::with_capacity(4096);
        // warm-up: one-time initialisation is allowed to allocate
        let start = ALLOCS.load(Ordering::SeqCst);
        detect_into(&warm, &mut dets);
        if !unicode {
            // control: the counter works (first use compiles the regexes)
            assert!(
                ALLOCS.load(Ordering::SeqCst) > start,
                "allocator not counting"
            );
        }
        entropy_secrets(&warm, &ent, Summation::Neumaier, |s, e, h| {
            spans.push((s, e, h))
        });
        compound_secrets(&warm, &comp, Summation::Neumaier, |s, e, h| {
            spans.push((s, e, h))
        });
        spans.clear();

        let before = ALLOCS.load(Ordering::SeqCst);
        detect_into(&hot, &mut dets);
        entropy_secrets(&hot, &ent, Summation::Neumaier, |s, e, h| {
            spans.push((s, e, h))
        });
        compound_secrets(&hot, &comp, Summation::Neumaier, |s, e, h| {
            spans.push((s, e, h))
        });
        let allocated = ALLOCS.load(Ordering::SeqCst) - before;

        // the scan did real work, so "no allocation" is not vacuous
        let types: std::collections::BTreeSet<_> = dets.iter().map(|d| d.entity_type).collect();
        for t in [
            "email",
            "credit_card",
            "phone",
            "ssn",
            "ipv4",
            "ipv6",
            "aws_key",
            "private_key",
        ] {
            assert!(types.contains(t), "no {t} detection (unicode={unicode})");
        }
        assert!(
            spans.len() >= 2,
            "entropy/compound found nothing (unicode={unicode})"
        );
        assert_eq!(
            allocated, 0,
            "hot path allocated {allocated} times (unicode={unicode})"
        );
    }
}
