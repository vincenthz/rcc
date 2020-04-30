#!/bin/sh

RUSTFLAGS="-C target_cpu=native" cargo +nightly run --release --features opt
