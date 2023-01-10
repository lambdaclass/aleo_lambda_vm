use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "benchmark_flamegraph")]
use pprof::criterion::PProfProfiler;

mod benchmarks;

fn run_benchmarks(_c: &mut Criterion) {
    cfg_if::cfg_if! {
        if #[cfg(any(feature = "vmtropy_backend", feature = "snarkvm_backend"))] {
            benchmarks::aleo_credits::execute_genesis(_c);
            benchmarks::aleo_credits::execute_mint(_c);
            benchmarks::aleo_credits::execute_transfer(_c);
            benchmarks::aleo_credits::execute_combine(_c);
            benchmarks::aleo_credits::execute_split(_c);
            benchmarks::aleo_credits::execute_fee(_c);
        }
    }
}

#[cfg(feature = "benchmark_flamegraph")]
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
    targets = run_benchmarks
}

#[cfg(all(not(feature = "benchmark_flamegraph")))]
criterion_group!(benches, run_benchmarks);

criterion_main!(benches);
