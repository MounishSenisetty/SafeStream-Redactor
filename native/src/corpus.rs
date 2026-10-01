//! Deterministic synthetic log corpus, shared by the benchmarks and the property
//! tests. Mirrors `benchmarks/baseline.py`: a "PII line" carries one specimen, a
//! "distractor line" is a realistic log line full of digits but with no PII, so
//! the digit-gated scanners do real work even at 0% density.

const SPECIMENS: &[&str] = &[
    "user bob.smith{n}@corp.example.com logged in",
    "client ip 10.20.{a}.{b} connected",
    "card 4111 1111 1111 1111 charged",
    "ssn 123-45-6789 on file",
    "call +1 (415) 555-0{n3} back",
    "key AKIAIOSFODNN7EXAMPLE rotated",
    "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 used",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0",
    "Student ID: 202184673 enrolled",
];

/// A small xorshift generator: deterministic across platforms and runs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// About `bytes` of log text in which `pii_per_mille` of 1000 lines carry PII.
pub fn log_corpus(bytes: usize, pii_per_mille: u64, seed: u64) -> String {
    let mut rng = Rng(seed | 1);
    let mut out = String::with_capacity(bytes + 256);
    while out.len() < bytes {
        if rng.below(1000) < pii_per_mille {
            let spec = SPECIMENS[rng.below(SPECIMENS.len() as u64) as usize];
            let line = spec
                .replace("{n3}", &format!("{:03}", rng.below(1000)))
                .replace("{n}", &rng.below(1000).to_string())
                .replace("{a}", &rng.below(256).to_string())
                .replace("{b}", &(1 + rng.below(254)).to_string());
            out.push_str(&line);
        } else {
            out.push_str(&format!(
                "2024-01-{:02}T00:00:{:02}Z INFO req {:04x} latency {}ms status 200 path \
                 /api/v1/users id {} cache hit bytes {}",
                1 + rng.below(28),
                rng.below(60),
                rng.below(0xFFFFFF),
                1 + rng.below(900),
                1000 + rng.below(999_000),
                10 + rng.below(100_000),
            ));
        }
        out.push('\n');
    }
    out
}
