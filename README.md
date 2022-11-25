# VMtropy
Proof of concept for a ZK snark-based VM running Aleo Instructions.

## Roadmap

### Milestone 1: Basic VM functionality

- Check with Valgrind and similar tools to see if running the VM on programs leaks memory or not.
- Make a Gant with the list and description of instructions needed to support the transfer and mint functions of the `credits.aleo` program.
- Implement said instructions and run the transfer and mint functions.

### Milestone 2: Tendermint integration

- Integrate our VM with the aleo-consensus node so they can execute the credits program to make transactions.
- Staking: Focus on the passage between public and private tokens.

## Out of scope for this current roadmap

- Other instructions not used by mint and transfer.
- 0ther data types not used by mint and transfer (U64 and records are enough).

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
cargo run --release -- execute <function_name> <path_to_your_program> <inputs>
```

As an example, you can run the sample program mentioned above with

```
cargo run --release -- execute hello ./examples/sample-program/sample.aleo 2u32 1u32
```

Underneath this runs the binary located in `./target/release`, so you can also do instead:

```
./target/release/vmtropy execute hello ./examples/sample-program/sample.aleo 2u32 1u32
```

after having run `cargo build --release`.

## Tests

Run tests with

```
make test
```
