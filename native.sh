#!/bin/sh

RUSTFLAGS="-C target_cpu=native" cargo run --release
