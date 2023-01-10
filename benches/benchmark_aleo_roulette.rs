use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "benchmark_flamegraph")]
use pprof::criterion::PProfProfiler;

mod benchmarks;

fn run_benchmarks(_c: &mut Criterion) {
    cfg_if::cfg_if! {
        if #[cfg(any(feature = "vmtropy_backend", feature = "snarkvm_backend"))] {
            benchmarks::aleo_roulette::benchmark_psd_hash_execution(_c);
            benchmarks::aleo_roulette::benchmark_mint_casino_token_record_execution(_c);
            benchmarks::aleo_roulette::benchmark_make_bet_execution(_c);
            benchmarks::aleo_roulette::benchmark_psd_bits_mod_execution(_c);
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
