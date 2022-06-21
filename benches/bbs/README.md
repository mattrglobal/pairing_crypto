# Benchmark

## Run

1. Run all benchmarks.

```shell
cargo bench
```

2. Run a single benchmark.

```shell
cargo bench --bench bbs_sign
```

## Html Report

Html report is generated in path `target/criterion/report/index.html`.

## Profiler

Profilers using [pprof](https://github.com/tikv/pprof-rs) exists in every crypto scheme directory to generate the flamegraphs.

To run profiler for BBS signature scheme,
```shell
cargo bench --bench bbs_profile -- --profile-time=5
```
Flamegraph file `flamegraph.svg` will be generated in `target/criterion/<name-of-the-benchmark>/profile/flamegraph.svg`.


