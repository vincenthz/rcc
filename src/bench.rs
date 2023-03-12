use ansi_term::Colour::{Blue, Purple, Red, Yellow};

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
            all_cycles
                .checked_div(self.counters.len() as u64)
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

pub fn benchmark<F>(tries: usize, f: F) -> BenchData
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
pub fn with_measurement<F>(f: F) -> (std::time::Duration, u64)
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

pub fn benchmark_hash<C, F, G>(
    name: &str,
    package: &str,
    tries: usize,
    data: &[u8],
    new: F,
    update: G,
) where
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

pub fn benchmark_kdf<F>(name: &str, package: &str, tries: usize, kdf: F)
where
    F: Fn() -> (),
{
    let bd = benchmark(tries, kdf);
    bd.reports(name, package);
}
