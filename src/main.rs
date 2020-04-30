use cryptoxide;

use blake2;
use sha2;

use core::arch::x86_64::__rdtscp;
use std::time::{Duration, SystemTime};

fn human_unit(v: u128) -> String {
    if v > 1024 * 1024 * 1024 {
        format!("{:.3} gb", v as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if v > 1024 * 1024 {
        format!("{:.2} mb", v as f64 / (1024.0 * 1024.0))
    } else if v > 1024 {
        format!("{:.2} kb", v as f64 / (1024.0))
    } else {
        format!("{} bytes", v)
    }
}

pub struct BenchData {
    datalen: usize,
    tries: usize,
    counters: Vec<u64>,
    durations: Vec<Duration>,
}

impl BenchData {
    pub fn reports(&self, name: &str) {
        let average_dur = self
            .durations
            .iter()
            .sum::<Duration>()
            .checked_div(self.tries as u32)
            .expect("cannot div");
        let average_cycles = self
            .counters
            .iter()
            .sum::<u64>()
            .checked_div(self.counters.len() as u64)
            .expect("cannot div");

        let speed = self.datalen as u128 * 1_000_000_000 / average_dur.as_nanos();
        let speed_h = human_unit(speed);

        let min = self.durations.iter().min().expect("min");
        let max = self.durations.iter().max().expect("max");

        let sd_n: i64 = self
            .durations
            .iter()
            .map(|d| ((d.as_nanos() as i128 - average_dur.as_nanos() as i128) as i64).pow(2))
            .sum();
        let sd = (sd_n as f64 / (self.durations.len() - 1) as f64).sqrt() / 1_000_000.0;

        println!(
            "{:25} | {:?} {:?} {:?} (sd={:.3} ms) cycles={} => {}/s",
            name, min, average_dur, max, sd, average_cycles, speed_h
        );
    }
}

fn benchmark_hash<C, F, G>(name: &str, tries: usize, data: &[u8], new: F, update: G)
where
    F: Fn() -> C,
    G: Fn(&mut C, &[u8]) -> (),
{
    let mut durations = Vec::with_capacity(tries);
    let mut counters = Vec::with_capacity(tries);

    /* prep cpu ... */
    let mut sh = new();
    update(&mut sh, data);

    for _ in 0..tries {
        let mut sh = new();
        let mut aux = 0u32;
        let start = SystemTime::now();
        let counter_start = unsafe { __rdtscp((&mut aux) as *mut u32) };
        update(&mut sh, data);
        let counter_end = unsafe { __rdtscp((&mut aux) as *mut u32) };
        let end = SystemTime::now();
        let dur = end
            .duration_since(start)
            .expect("Clock may have gone backwards");
        durations.push(dur);
        if counter_end > counter_start {
            counters.push(counter_end - counter_start);
        }
    }
    let bd = BenchData {
        datalen: data.len(),
        tries,
        durations,
        counters,
    };

    bd.reports(name);
    std::thread::sleep(std::time::Duration::from_secs(1));
}

fn main() {
    let data = vec![0u8; 10 * 1024 * 1024];

    let tries = 24;

    macro_rules! bench_hash {
        ($name: expr, $cstr: expr, $update: expr) => {
            benchmark_hash($name, tries, &data[..], || $cstr, $update);
        };
    }

    {
        use cryptoxide::{blake2b::Blake2b, digest::Digest};
        bench_hash!("cryptoxide::blake2b", Blake2b::new(64), |c, d| {
            c.input(d)
        });
    }

    {
        use blake2::{Blake2b, Digest};
        bench_hash!("blake2::blake2b", Blake2b::new(), |c, d| { c.input(d) });
    }

    {
        use cryptoxide::{blake2s::Blake2s, digest::Digest};
        bench_hash!("cryptoxide::blake2s", Blake2s::new(32), |c, d| {
            c.input(d)
        });
    }

    {
        use blake2::{Blake2s, Digest};
        bench_hash!("blake2::blake2s", Blake2s::new(), |c, d| { c.input(d) });
    }

    {
        use cryptoxide::{digest::Digest, sha2::Sha256};
        bench_hash!("cryptoxide::sha256", Sha256::new(), |c, d| { c.input(d) });
    }

    {
        use sha2::{Digest, Sha256};
        bench_hash!("sha2::sha256", Sha256::new(), |c, d| { c.input(d) });
    }

    {
        use cryptoxide::{mac::Mac, poly1305::Poly1305};
        let key = [2u8; 32];
        bench_hash!("cryptoxide::poly1305", Poly1305::new(&key), |c, d| {
            c.input(d)
        });
    }
    {
        use poly1305::Poly1305;
        use universal_hash::UniversalHash;
        let key = [2u8; 32];
        bench_hash!(
            "poly1305::poly1305",
            Poly1305::new(key.as_ref().into()),
            |c, d| { c.update(d) }
        );
    }
}
