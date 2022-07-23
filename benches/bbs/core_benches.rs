use pairing_crypto::bbs::benchmarks::BenchHelper;

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use std::time::Duration;

const MAX_LOG_POW: u32 = 4;

fn core_benchmark(c: &mut Criterion) {
    let mut benchmarker = BenchHelper::init((10 as i32).pow(MAX_LOG_POW)).unwrap();

    for messages_num in (0..=MAX_LOG_POW).map(|el| {(10 as i32).pow(el as u32)}) {
        println!("messages number = {}", messages_num);
        println!("==========================================================");

        // Signature benchmarks
        c.bench_function(
            &format!("sign - total messages {}", messages_num),
            |b| {
                b.iter(|| {
                    benchmarker.sign_bench_helper(messages_num);
                })
            },
        );

        // Set the signature that will be verified
        benchmarker.set_signature(messages_num);

        c.bench_function(
            &format!("verify - total messages {}", messages_num),
            |b| {
                b.iter(|| {
                    benchmarker.sig_verify_bench_helper(messages_num);
                })
            },
        );

        // Proof benchmarks
        c.bench_function(
            &format!("proof generation - total messages {}", messages_num),
            |b| {
                b.iter(|| {
                    benchmarker.proof_gen_bench_helper(messages_num);
                })
            },
        );

        // Set the proof that will be verifier
        benchmarker.set_proof(messages_num);

        c.bench_function(
            &format!("proof verify - total messages {}", messages_num),
            |b| b.iter(|| benchmarker.proof_verify_bench_helper(messages_num)),
        );
    }
}

criterion_group!(
    name = bbs_sign_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(20));
    targets = core_benchmark
);

criterion_main!(bbs_sign_benches);
