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

## Roadmap

The VM does not currently support all data types and opcodes. A complete implementation will take around a month more of work. Below is a list of the instructions and data types missing.

### Missing data types

- `Group`
- All signed Integers. `I8`, `I16`, `I32`, `I64` and `I128`.
- `Scalar`
- `String`
- `Interface`

### Missing instructions

- `abs` and `abs.w` (absolute value and its wrapping version)
- `add.w`
- `and`
- `assert.eq` and `assert.neq`
- The `BHP` and `Pedersen` commit instructions with all its variants (`commit.bhp256`, `commit.bhp512`, `commit.bhp768`, `commit.bhp1024`, `commit.ped64` and `commit.ped128`).
- `div.w`
- `double`
- `gt`, `gte`, `lt` and `lte`
- All hash instructions expect for `hash.psd2` (`hash.bhp256`, `hash.bhp512`, `hash.bhp768`, `hash.bhp1024`, `hash.ped64`, `hash.ped128`, `hash.psd4` and `hash.psd8`).
- `inv`
- `is.neq`
- `mul.w`
- `nand`
- `neg`
- `nor`, `not`, `or` and `xor`
- `pow` and `pow.w`
- `rem` and `rem.w`
- `shl.w` and `shr.w`
- `sqrt`
- `sub.w`
- `square`

## Tests

Run tests with

```
make test
```

# Aleo Internal Documentation [WIP]
# SnarkVM Encryption

Because Aleo is meant to be fully private, users's records need to be stored encrypted on-chain, so only the people who possess the corresponding view key can see them.

There's a catch here though. When, for instance, user `A` wants to send money to user `B`, they have to create a record owned by `B` *and encrypt it so that only `B` can decrypt it* to store on the blockchain. This means the encryption scheme used by Aleo cannot be symmetric, as that would require user `A` to have `B`'s view key to send them money; not just their address.

This is why the encryption scheme used by Aleo is essentially asymmetric. Records are encrypted using the owner's address, but they can only be decrypted with their view key. The scheme used is called `ECIES` (*Elliptic Curve Integrated Encryption Scheme*).

What follows is a description of how this scheme works. Keep in mind that in Aleo, a view-key/address pair is nothing more than an elliptic curve private/public key-pair.

- `B` retrieves `A`'s address.
- `B` generates an ephemeral (one-time only) elliptic curve key-pair.
- `B` uses Diffie-Hellman with their ephemeral private key and `A`'s address to generate a symmetric encryption key.
- `B` encrypts the record with the symmetric key, and publishes both the encrypted record and the ephemeral public key.
- When `A` wants to decrypt their record, they use their view key and the published ephemeral public key to derive (through Diffie-Helman) the symmetric encryption key.

In Aleo terminology, the symmetric encryption key for a record is called the `record view key`. It is derived from the `transition view key`, which acts as a sort of "Master" encryption key for all the records involved in the transition.

The symmetric encryption scheme used by Aleo's ECIES implementation is not a traditional one like `AES`, but rather a custom one using the Poseidon hash function.

There are actually some additions to this ECIES scheme in Aleo, with the goal of allowing a user to tell whether an encrypted record belongs to them or not without doing the full decryption. Some documentation on it can be found [here](https://github.com/AleoHQ/snarkVM/issues/359). The general idea remains the same though.

## How this maps to SnarkVM's API

The record encryption API in SnarkVM takes a `randomizer` as argument. There's a lot of different names being thrown around here, but this randomizer is just a value derived from the `transition view key`, which in turn allows to derive the `record view key`. You can see this happening in the code, as the `encrypt` method

```rust
/// Encrypts `self` for the record owner under the given randomizer.
pub fn encrypt(&self, randomizer: &Scalar<A>) -> Record<A, Ciphertext<A>> {
    // Ensure the randomizer corresponds to the record nonce.
    A::assert_eq(&self.nonce, A::g_scalar_multiply(randomizer));
    // Compute the record view key.
    let record_view_key = ((*self.owner).to_group() * randomizer).to_x_coordinate();
    // Encrypt the record.
    self.encrypt_symmetric(record_view_key)
}
```

just calls `encrypt_symmetric` after deriving the `record view key` through a simple elliptic curve calculation.

This `randomizer` is also called the record's `nonce`. They call it `nonce` because they also use it as a value to make the record's commitment unique.

## How is the transition view key generated?

When a user creates a transition, they create what `Aleo` calls a `Request`. As part of creating this request, they have to generate a value called the `transition secret key`. This is nothing more than the hash of the caller's private key and a random number.

From this secret key, a key-pair is generated: the `transition view key` and the `transition public key`. As explained above, the `transition view key` is the private key used for ECIES encryption, and the `transition public key` is the corresponding public key, which has to be published as part of the transaction so the owner can decrypt.
