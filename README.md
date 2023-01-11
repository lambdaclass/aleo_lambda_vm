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

# Aleo Internal Documentation [WIP]
# Snarkvm Encryption

## Record Encryption

- Take a random field element called `randomizer` as an argument, which is the record's nonce. TODO: Explain how nonces are generated?
- Generate a `record view key` from the record owner's address and the `randomizer`. This record view key is NOT the user's view key, it's the simmetric encryption key used for both encrypting and decrypting this specific record.
- Use a symmetric encryption scheme involving the poseidon hash function and the record view key to encrypt the record.

## Record Decryption

- Take the view key as argument, recover the record view key from it and the record nonce.
- Decrypt the record through the symmetric encryption scheme described above.

## Record View key generation

The person doing the encryption derives the record view key through the following computation:

```
let record_view_key = (address * randomizer).to_x_coordinate();
```

where the `randomizer` must satisfy the following

```
nonce == g_scalar_multiply(randomizer)
```

with `g_scalar_multiply` a function that `Returns the scalar multiplication on the generator G`.

The person doing the decryption derives the record view key by doing

```
let record_view_key = (view_key * nonce).to_x_coordinate();
```

## How is the nonce generated?

EXPLAIN: Transition secret key, transition view key, transition public key.

Records are created when someone wants to perform a transaction to consume a record and create one or multipe output records. These records that are created might not belong to the caller, but they still need to be encrypted. This is done through the encryption discussed above. The only thing left to explain is how the nonce is generated.

The nonce is generated in the `Request::sign`. This is the function called when crafting a transaction. The steps are the following:

- Retrieve the signature secret key (`sk_sig`) from the private key. An Aleo private key is actually composed of three things, not just one number. One of these numbers is this signature secret key. It's just a random value.
- Sample a random field element, which we call `nonce`. This is NOT the final nonce we are trying to generate, just an "intermediate" one.
- Compute the `transition secret key` `tsk` as the hash of the `sk_sig || nonce`. This is the key that needs to be kept secret for the encryption. If this leaks, people can decrypt the output records for this transition, regardless of who they belong to.
- Compute the `transition public key` as `g ^ tsk`. This value is going to be published as part of the transition in the blockchain. TODO: What is this key for?
- Compute the `transition view key` as `caller_address ^ tsk`. It's this transition view key that is used to derive the nonce. 
