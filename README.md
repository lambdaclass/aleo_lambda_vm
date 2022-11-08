# VMtropy
Proof of concept for a ZK snark-based VM

## Running examples:

``` shell
cargo test --release --example test-circuit
cargo test --release --example manual-constraints
cargo test --release --example merkle-tree
```

You can check out the code for them under the `examples` directory, and a thorugh explanation of `test-circuit` and `manual-constraints` in `docs/circuits_and_proofs.md`.
