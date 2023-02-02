.PHONY: clippy test

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

# BACKEND = lambdavm_backend or snarkvm_backend
benchmark_aleo_roulette:
	cargo criterion --features ${BACKEND} --bench benchmark_aleo_roulette

# BACKEND = lambdavm_backend or snarkvm_backend
benchmark_aleo_credits:
	cargo criterion --features ${BACKEND} --bench benchmark_aleo_credits

# Benches credits.aleo functions first with lambdavm's backend and then with
# snarkvm's backend.
benchmark_aleo_credits_backends_comparison:
	cargo criterion --features lambdavm_backend --bench benchmark_aleo_credits \
	&& cargo criterion --features snarkvm_backend --bench benchmark_aleo_credits

# Benches roulette.aleo functions first with lambdavm's backend and then with
# snarkvm's backend.
benchmark_aleo_roulette_backends_comparison:
	cargo criterion --features lambdavm_backend --bench benchmark_aleo_roulette \
	&& cargo criterion --features snarkvm_backend --bench benchmark_aleo_roulette
