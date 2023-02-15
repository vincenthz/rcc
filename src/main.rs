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
        let all_cycles = self.counters.iter().sum::<u64>();
        let average_cycles = if self.counters.len() > 0 {
            all_cycles.checked_div(self.counters.len() as u64)
                .expect("cannot div")
        } else {
            0
        };

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
            "{:16} -- {:16}  [ {} .. ~{} .. {} ]   {}={} {} ; {}={} {}",
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

    /* prep cpu/memory with one unmeasured call to f... */
    f();

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

#[inline]
fn with_measurement<F>(f: F) -> (std::time::Duration, u64)
where
    F: FnOnce() -> (),
{
    let mut aux = 0u32;
    let start = SystemTime::now();
    let counter_start = counter(&mut aux);
    f();
    let counter_end = counter(&mut aux);
    let end = SystemTime::now();
    let dur = end
        .duration_since(start)
        .expect("Clock may have gone backwards");
    (dur, counter_end.saturating_sub(counter_start))
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
        let (dur, counter) = with_measurement(|| {
            update(&mut sh, data);
        });
        durations.push(dur);
        if counter > 0 {
            counters.push(counter);
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

fn benchmark_kdf<F>(name: &str, package: &str, tries: usize, kdf: F)
where
    F: Fn() -> (),
{
    let bd = benchmark(tries, kdf);
    bd.reports(name, package);
}

struct ExecuteParams {
    repeat: usize,
    selector: Option<String>,
}

fn group<F>(execute_params: &ExecuteParams, group_name: &str, f: F)
where
    F: FnOnce() -> (),
{
    match &execute_params.selector {
        None => f(),
        Some(n) if n == group_name || group_name.starts_with(n) => f(),
        Some(_) => (),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sel = if args.len() <= 1 {
        None
    } else {
        Some(args[1].clone())
    };

    let data = vec![0u8; 10 * 1024 * 1024];

    let tries = 16;

    macro_rules! bench_hash {
        ($name: expr, $package: expr, $cstr: expr, $update: expr) => {
            benchmark_hash($name, $package, tries, &data[..], || $cstr, $update);
        };
    }

    let e = ExecuteParams {
        repeat: 3,
        selector: sel,
    };

    // packages we bench
    const PKG_CRYPTOXIDE: &str = "cryptoxide";
    const PKG_DALEK: &str = "dalek";
    const PKG_SHA1: &str = "sha1";
    const PKG_SHA2: &str = "sha2";
    const PKG_SHA3: &str = "sha3";
    const PKG_ARGON2: &str = "argon2";
    const PKG_CHACHA20: &str = "chacha20";
    const PKG_BLAKE2: &str = "blake2";
    const PKG_RING: &str = "ring";

    for _ in 0..e.repeat {
        group(&e, "blake2b", || {
            {
                use cryptoxide::hashing::blake2b::Blake2b;
                bench_hash!("blake2b", PKG_CRYPTOXIDE, Blake2b::<512>::new(), |c, d| {
                    c.update_mut(d)
                });
            }

            {
                use blake2::{Blake2b512, Digest};
                bench_hash!("blake2b", PKG_BLAKE2, Blake2b512::new(), |c, d| {
                    c.update(d)
                });
            }
        });

        group(&e, "blake2s", || {
            {
                use cryptoxide::hashing::blake2s::Blake2s;
                bench_hash!("blake2s", PKG_CRYPTOXIDE, Blake2s::<256>::new(), |c, d| {
                    c.update_mut(d)
                });
            }

            {
                use blake2::{Blake2s256, Digest};
                bench_hash!("blake2s", PKG_BLAKE2, Blake2s256::new(), |c, d| {
                    c.update(d)
                });
            }
        });

        group(&e, "sha1", || {
            {
                use cryptoxide::hashing::sha1::Sha1;
                bench_hash!("sha1", PKG_CRYPTOXIDE, Sha1::new(), |c, d| {
                    c.update_mut(d)
                });
            }

            {
                use sha1::Sha1;
                bench_hash!("sha1", PKG_SHA1, Sha1::new(), |c, d| { c.update(d) });
            }
        });

        group(&e, "sha256", || {
            {
                use cryptoxide::hashing::sha2::Sha256;
                bench_hash!("sha256", PKG_CRYPTOXIDE, Sha256::new(), |c, d| {
                    c.update_mut(d)
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

        group(&e, "sha512", || {
            {
                use cryptoxide::hashing::sha2::Sha512;
                bench_hash!("sha512", PKG_CRYPTOXIDE, Sha512::new(), |c, d| {
                    c.update_mut(d)
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

        group(&e, "sha3-256", || {
            {
                use cryptoxide::hashing::sha3::Sha3_256;
                bench_hash!("sha3-256", PKG_CRYPTOXIDE, Sha3_256::new(), |c, d| {
                    c.update_mut(d)
                });
            }

            {
                use sha3::{Digest, Sha3_256};
                bench_hash!("sha3-256", PKG_SHA3, Sha3_256::new(), |c, d| {
                    c.update(d)
                });
            }
        });

        group(&e, "argon2", || {
            const ARGON_SALT: &[u8] = b"saltsaltsaltsalt";
            const ARGON_PASSWORD: &[u8] = b"password";
            const ARGON_TRIES: usize = 50;

            const ARGON_EXPECT: &[u8] = &[
                220, 38, 26, 14, 138, 27, 21, 170, 107, 15, 77, 135, 76, 197, 85, 68, 187, 43, 74,
                2, 99, 100, 174, 80, 154, 166, 22, 157, 96, 196, 2, 92,
            ];
            {
                use cryptoxide::kdf::argon2;

                benchmark_kdf("argon2d", PKG_CRYPTOXIDE, ARGON_TRIES, || {
                    let params = argon2::Params::argon2d()
                        .memory_kb(4096)
                        .unwrap()
                        .parallelism(1)
                        .unwrap()
                        .iterations(3)
                        .unwrap();
                    let out = argon2::argon2::<32>(&params, ARGON_PASSWORD, ARGON_SALT, &[], &[]);
                    assert_eq!(out, ARGON_EXPECT);
                });
            }

            {
                benchmark_kdf("argon2d", PKG_ARGON2, ARGON_TRIES, || {
                    let mut config = argon2::Config::default();
                    config.mem_cost = 4096;
                    config.lanes = 1;
                    config.time_cost = 3;
                    config.hash_length = 32;
                    config.variant = argon2::Variant::Argon2d;
                    let out = argon2::hash_raw(ARGON_PASSWORD, ARGON_SALT, &config).unwrap();
                    assert_eq!(out, ARGON_EXPECT);
                });
            }
        });

        group(&e, "poly1305", || {
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

        group(&e, "chacha20", || {
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

        group(&e, "x25519::base", || {
            {
                use cryptoxide::curve25519::curve25519_base;

                let bd = benchmark(tries, || {
                    let _out = curve25519_base(&[1; 32]);
                    ()
                });
                bd.reports("x25519::base", PKG_CRYPTOXIDE)
            }
            {
                use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

                let bd = benchmark(tries, || {
                    let _out = x25519([1; 32], X25519_BASEPOINT_BYTES);
                    ()
                });
                bd.reports("x25519::base", PKG_DALEK)
            }
        });

        group(&e, "x25519::dh", || {
            {
                use cryptoxide::curve25519::curve25519;

                let bd = benchmark(tries, || {
                    let _out = curve25519(&[1; 32], &[2; 32]);
                    ()
                });
                bd.reports("x25519::dh", PKG_CRYPTOXIDE)
            }
            {
                use x25519_dalek::x25519;

                let bd = benchmark(tries, || {
                    let _out = x25519([1; 32], [2; 32]);
                    ()
                });
                bd.reports("x25519::dh", PKG_DALEK)
            }
        });

        group(&e, "ed25519::sign", || {
            let message = "messages".as_bytes();
            let secret_bytes = [1u8; 32];

            {
                use cryptoxide::ed25519;

                let (secret, _) = ed25519::keypair(&secret_bytes);
                let bd = benchmark(tries, || {
                    let _signature = ed25519::signature(message, &secret);
                    ()
                });
                bd.reports("ed25519::sign", PKG_CRYPTOXIDE)
            }
            {
                use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};

                let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
                let public: PublicKey = (&secret).into();
                let keypair: Keypair = Keypair { secret, public };

                let bd = benchmark(tries, || {
                    let signature: Signature = keypair.sign(message);
                    let _ = signature.to_bytes();
                    ()
                });
                bd.reports("ed25519::sign", PKG_DALEK)
            }
        });

        group(&e, "ed25519::verify", || {
            let message = "messages".as_bytes();
            let secret_bytes = [1u8; 32];

            {
                use cryptoxide::ed25519;

                let (secret, public) = ed25519::keypair(&secret_bytes);
                let signature = ed25519::signature(message, &secret);
                let bd = benchmark(tries, || {
                    let _: bool = ed25519::verify(message, &public, &signature);
                    ()
                });
                bd.reports("ed25519::verify", PKG_CRYPTOXIDE)
            }
            {
                use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};

                let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
                let public: PublicKey = (&secret).into();
                let keypair: Keypair = Keypair { secret, public };
                let signature: Signature = keypair.sign(message);

                let bd = benchmark(tries, || {
                    let _ = public.verify(message, &signature);
                    ()
                });
                bd.reports("ed25519::verify", PKG_DALEK)
            }
        });

        println!("")
    }
}
