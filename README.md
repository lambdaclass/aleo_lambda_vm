# VMtropy
Proof of concept for a ZK snark-based VM running Aleo Instructions.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)

## Usage

### As a library

You can find an example where we run a program under `examples/sample-program`. To run it:

```
cargo run --release --example sample-program
```

### Through the CLI

To execute an aleo program, run

```
cargo run --release -- <path_to_your_program> <function_name>
```

As an example, you can run the sample program mentioned above with

```
cargo run --release -- ./examples/sample-program/sample.aleo hello
```

## Tests

Run tests with

```
make test
```
