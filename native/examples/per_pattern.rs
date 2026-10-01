//! Time each regex pattern alone over the 0%-PII corpus (diagnostics only).
use safestream_native::{corpus::log_corpus, PATTERNS};
use std::time::Instant;

fn main() -> Result<(), regex::Error> {
    let text = log_corpus(4 << 20, 0, 7);
    let mb = text.len() as f64 / (1 << 20) as f64;
    for p in PATTERNS {
        let Ok(re) = regex::Regex::new(&p.source.replace(r"\s", r"[\s\x1C-\x1F]")) else {
            println!("{:16} (scanner, not a regex)", p.name);
            continue;
        };
        let mut best = f64::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let n = re.find_iter(&text).count();
            std::hint::black_box(n);
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!("{:16} {:9.0} MiB/s", p.name, mb / best);
    }
    Ok(())
}
