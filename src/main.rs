use ansi_term::Colour::{Blue, Purple, Red, Yellow};

use cryptoxide;

use blake2;
use sha2;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__rdtscp;

#[cfg(not(target_arch = "x86_64"))]
unsafe fn __rdtscp(aux: *mut u32) -> u64 {
    *aux = 0;
    0
}

#[inline]
fn counter(aux: &mut u32) -> u64 {
    unsafe { __rdtscp(aux as *mut u32) }
}

use std::time::{Duration, SystemTime};

fn human_unit(v: u128) -> String {
    let (number, unit) = if v > 1024 * 1024 * 1024 {
        (
            format!("{:.3}", v as f64 / (1024.0 * 1024.0 * 1024.0)),
            "gb",
        )
    } else if v > 1024 * 1024 {
        (format!("{:.2}", v as f64 / (1024.0 * 1024.0)), "mb")
    } else if v > 1024 {
        (format!("{:.2}", v as f64 / (1024.0)), "kb")
    } else {
        (format!("{}", v), "bytes")
    };
    format!("{} {}", Purple.paint(&number), Red.paint(unit))
}

pub struct BenchData {
    datalen: Option<usize>,
    tries: usize,
    counters: Vec<u64>,
    durations: Vec<Duration>,
}

impl BenchData {
    pub fn set_datalen(mut self, size: usize) -> Self {
        self.datalen = Some(size);
        self
    }
}

impl BenchData {
    pub fn reports(&self, name: &str, package: &str) {
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
            .expect("cannot div")
            .checked_div(self.tries as u64)
            .expect("cannot div");

        let speed_string = match self.datalen {
            None => String::new(),
            Some(datalen) => {
                let speed = datalen as u128 * 1_000_000_000 / average_dur.as_nanos();
                let speed_h = human_unit(speed);
                format!("=> {}{}", speed_h, Red.paint("/s"))
            }
        };

        let min = self.durations.iter().min().expect("min");
        let max = self.durations.iter().max().expect("max");

        let sd_n: i64 = self
            .durations
            .iter()
            .map(|d| ((d.as_nanos() as i128 - average_dur.as_nanos() as i128) as i64).pow(2))
            .sum();
        let sd = (sd_n as f64 / (self.durations.len() - 1) as f64).sqrt() / 1_000_000.0;

        fn print_dur(dur: Duration) -> String {
            // "1.234xy"
            let secs = dur.as_secs();
            //let nanosecs = dur.subsec_nanos();
            if secs > 1 {
                format!(
                    "{:3}.{:02}s ",
                    dur.as_secs(),
                    (dur.subsec_millis() % 1000) / 10
                )
            } else if dur.subsec_millis() > 1 {
                let micros = (dur.subsec_micros() % 1000) / 10;
                format!("{:3}.{:02}ms", dur.subsec_millis(), micros)
            } else if dur.subsec_micros() > 1 {
                let nanos = (dur.subsec_nanos() % 1000) / 10;
                format!("{:3}.{:02}us", dur.subsec_micros(), nanos)
            } else {
                format!("{:3}ns", dur.subsec_nanos())
            }
        }

        println!(
            "{:10} -- {:16}  [ {} .. ~{} .. {} ]   {}={} {} ; {}={} {}",
            name,
            package,
            Yellow.paint(&print_dur(*min)),
            Yellow.paint(&print_dur(average_dur)),
            Yellow.paint(&print_dur(*max)),
            Blue.paint("deviation"),
            Purple.paint(&format!("{:.3}", sd)),
            Red.paint("ms"),
            Blue.paint("cycle"),
            Purple.paint(&format!("{}", average_cycles)),
            speed_string,
        );
    }
}

fn benchmark<F>(tries: usize, f: F) -> BenchData
where
    F: Fn() -> (),
{
    let mut durations = Vec::with_capacity(tries);
    let mut counters = Vec::with_capacity(tries);

    for _ in 0..tries {
        let mut aux = 0u32;
        let start = SystemTime::now();
        let counter_start = counter(&mut aux);
        f();
        let counter_end = counter(&mut aux);
        let end = SystemTime::now();
        let dur = end
            .duration_since(start)
            .expect("Clock may have gone backwards");
        durations.push(dur);
        if counter_end >= counter_start {
            counters.push(counter_end - counter_start);
        } else {
            counters.push(0)
        }
    }
    let bd = BenchData {
        datalen: None,
        tries,
        durations,
        counters,
    };
    bd
}

fn benchmark_hash<C, F, G>(name: &str, package: &str, tries: usize, data: &[u8], new: F, update: G)
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
        let counter_start = counter(&mut aux);
        update(&mut sh, data);
        let counter_end = counter(&mut aux);
        let end = SystemTime::now();
        let dur = end
            .duration_since(start)
            .expect("Clock may have gone backwards");
        durations.push(dur);
        if counter_end >= counter_start {
            counters.push(counter_end - counter_start);
        }
    }
    let bd = BenchData {
        datalen: Some(data.len()),
        tries,
        durations,
        counters,
    };

    bd.reports(name, package);

    // cool down time
    std::thread::sleep(std::time::Duration::from_secs(1));
}

fn group<F>(_group_name: &str, f: F)
where
    F: FnOnce() -> (),
{
    f()
}

fn main() {
    let data = vec![0u8; 10 * 1024 * 1024];

    let tries = 24;

    macro_rules! bench_hash {
        ($name: expr, $package: expr, $cstr: expr, $update: expr) => {
            benchmark_hash($name, $package, tries, &data[..], || $cstr, $update);
        };
    }

    let repeat = 3;

    // packages we bench
    const PKG_CRYPTOXIDE: &str = "cryptoxide";
    const PKG_DALEK: &str = "dalek";
    const PKG_SHA2: &str = "sha2";
    const PKG_CHACHA20: &str = "chacha20";
    const PKG_BLAKE2: &str = "blake2";
    const PKG_RING: &str = "ring";

    for _ in 0..repeat {
        group("blake2b", || {
            {
                use cryptoxide::{blake2b::Blake2b, digest::Digest};
                bench_hash!("blake2b", PKG_CRYPTOXIDE, Blake2b::new(64), |c, d| {
                    c.input(d)
                });
            }

            {
                use blake2::{Blake2b, Digest};
                bench_hash!("blake2b", PKG_BLAKE2, Blake2b::new(), |c, d| {
                    c.update(d)
                });
            }
        });

        group("blake2s", || {
            {
                use cryptoxide::{blake2s::Blake2s, digest::Digest};
                bench_hash!("blake2s", PKG_CRYPTOXIDE, Blake2s::new(32), |c, d| {
                    c.input(d)
                });
            }

            {
                use blake2::{Blake2s, Digest};
                bench_hash!("blake2s", PKG_BLAKE2, Blake2s::new(), |c, d| {
                    c.update(d)
                });
            }
        });

        group("sha256", || {
            {
                use cryptoxide::{digest::Digest, sha2::Sha256};
                bench_hash!("sha256", PKG_CRYPTOXIDE, Sha256::new(), |c, d| {
                    c.input(d)
                });
            }

            {
                use sha2::{Digest, Sha256};
                bench_hash!("sha256", PKG_SHA2, Sha256::new(), |c, d| { c.update(d) });
            }

            {
                use ring::digest;
                bench_hash!(
                    "sha256",
                    PKG_RING,
                    digest::Context::new(&digest::SHA256),
                    |c, d| { c.update(d) }
                );
            }
        });

        group("sha512", || {
            {
                use cryptoxide::{digest::Digest, sha2::Sha512};
                bench_hash!("sha512", PKG_CRYPTOXIDE, Sha512::new(), |c, d| {
                    c.input(d)
                });
            }

            {
                use sha2::{Digest, Sha512};
                bench_hash!("sha512", PKG_SHA2, Sha512::new(), |c, d| { c.update(d) });
            }

            {
                use ring::digest;
                bench_hash!(
                    "sha512",
                    PKG_RING,
                    digest::Context::new(&digest::SHA512),
                    |c, d| { c.update(d) }
                );
            }
        });

        group("poly1305", || {
            {
                use cryptoxide::{mac::Mac, poly1305::Poly1305};
                let key = [2u8; 32];
                bench_hash!("poly1305", PKG_CRYPTOXIDE, Poly1305::new(&key), |c, d| {
                    c.input(d)
                });
            }
            /*
            {
                use poly1305::Poly1305;
                use universal_hash::NewUniversalHash;
                let key = [2u8; 32];
                bench_hash!(
                    "poly1305::poly1305",
                    Poly1305::new(key.as_ref().into()),
                    |c, d| { c.compute_unpadded(&d); }
                );
            }
            */
        });

        group("chacha20", || {
            let key: [u8; 32] = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let nonce: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            let size = 10 * 1024 * 1024;
            {
                use cryptoxide::chacha20::ChaCha20;

                let bd = benchmark(tries, || {
                    let mut data = vec![0u8; size];
                    let mut cipher = ChaCha20::new(&key, &nonce);
                    cipher.process_mut(&mut data);
                });
                bd.set_datalen(size).reports("chacha20", PKG_CRYPTOXIDE)
            }
            {
                use chacha20::cipher::{NewCipher, StreamCipher};
                use chacha20::{ChaCha20, Key, Nonce};

                let bd = benchmark(tries, || {
                    let mut data = vec![0u8; size];
                    let key = Key::from_slice(&key);
                    let nonce = Nonce::from_slice(&nonce);
                    let mut cipher = ChaCha20::new(&key, &nonce);
                    cipher.apply_keystream(&mut data);
                });
                bd.set_datalen(size).reports("chacha20", PKG_CHACHA20)
            }
        });

        group("curve25519", || {
            {
                use cryptoxide::curve25519::curve25519_base;

                let bd = benchmark(tries, || {
                    let _out = curve25519_base(&[1; 32]);
                    ()
                });
                bd.reports("curve25519", PKG_CRYPTOXIDE)
            }
            {
                use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

                let bd = benchmark(tries, || {
                    let _out = x25519([1; 32], X25519_BASEPOINT_BYTES);
                    ()
                });
                bd.reports("curve25519", PKG_DALEK)
            }
        });
        println!("")
    }
}
