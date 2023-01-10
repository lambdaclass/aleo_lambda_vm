.PHONY: clippy test


clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

# BACKEND = vmtropy_backend or snarkvm_backend
benchmark_aleo_roulette:
	cargo bench --features ${BACKEND} --bench benchmark_aleo_roulette

# BACKEND = vmtropy_backend or snarkvm_backend
benchmark_aleo_credits:
	cargo bench --features ${BACKEND} --bench benchmark_aleo_credits

# Benches credits.aleo functions first with vmtropy's backend and then with
# snarkvm's backend.
benchmark_aleo_credits_backends_comparison:
	cargo bench --features vmtropy_backend --bench benchmark_aleo_credits \
	&& cargo bench --features snarkvm_backend --bench benchmark_aleo_credits

# Benches roulette.aleo functions first with vmtropy's backend and then with
# snarkvm's backend.
benchmark_aleo_roulette_backends_comparison:
	cargo bench --features vmtropy_backend --bench benchmark_aleo_roulette \
	&& cargo bench --features snarkvm_backend --bench benchmark_aleo_roulette
