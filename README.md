# Aleo Lambda VM
Proof of concept for a ZK SNARK based VM running Aleo Instructions.

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

The VM does not currently support all data types and opcodes. A complete implementation will take around a month more of work. Hopefully it will be ready by the end of February 2023. Below is a list of the instructions and data types missing. 

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

# Repo walkthrough
## Introduction

At a high level, this VM provides an API to take an Aleo program that looks like this

```aleo
program main.aleo;
        
function add:
    input r0 as u16.public;
    input r1 as u16.private;
    add r0 r1 into r2;
    output r2 as u16.public;
```

and then

- Generate a pair of proving and verifying keys for it. We call this *building* the program.
- Turn the program into an Arkworks' circuit, then execute it with a given set of inputs, producing a proof of its execution.
- Verify a given proof.

The biggest task here is turning the program into an arithmetic circuit, as the rest of the work, namely generating the proof and verifying it, is pretty straightforward with the Arkworks API (building the program, as we'll see later, is almost the same as turning it into a circuit and executing). 

Before continuing, you should have at least a basic understanding of arithmetic circuits and how Arkworks lets you work with them. You can read about it [here](https://lambdaclass.github.io/simpleworks/overview.html).

To generate the circuit, we go through the following steps:

- Take the program's source code and parse it into a `Program` struct containing all the relevant information about the program (a list of all `input` and `output` instructions, whether they are `public` or `private`, a list of all regular instructions like `add` and its operands, etc). We currently rely on SnarkVM's parser, but plan on writing our own eventually.
- Instantiate an Arkworks `ConstraintSystem` struct, which is going to hold all our circuit's constraints by the end.
- For every `input` instruction, instantiate its corresponding Gadget with the appropriate visibility (public input if it's `public`, witness if it's `private`). In our example, the first instruction `input r0 as u16.public` becomes a call to `UInt16Gadget.new_input(...)` and the second instruction becomes `UInt16Gadget.new_witness(...)`.
- For every regular instruction, we use the gadget's associated function to perform the operation and generate the constraints for it inside our `ConstraintSystem`. In our example, when we encounter the `add r0 r1 into r2;` instruction we call `UInt16Gadget.addmany(...)`. This is an arkworks provided function that will take a list of `UInt16`s, add them, implicitly mutate the `constraint_system` with all the associated constraints, then return the value of the sum. Not all instructions have a corresponding arkworks function implemented, so for those we had to implement our own.
- For every `output` instruction, assign to the register the computed value.

Because a program can have multiple registers interacting with each other, to do the above we have to keep track of each register and its value as we go. For this we keep an internal hash table throughout execution, called `function_variables`.

In the next sections, we go through the details of how building, executing, and then verifying the execution works.

## Building a program

The `build_program` function will take in a string with the program's source code and return a `Program` struct along with a `ProgramBuild`, which is a map with all the proving/verifying keys for each program's function.

```rust
let (program, _build) = build_program(&program_string).unwrap();
```

For this usecase we won't need the latter. Internally, this function is taking care of instantiating the Universal SRS, building the circuit to then generate the proving and verifying keys. 

## Executing a function

To execute a program's function, you call `execute_function`. It takes the parsed `program`, the `function`, and the `user_inputs` as parameters.

```rust
// Run the `hello` function defined in the `sample.aleo` program
let (_compiled_function_variables, proof) =
        vmtropy::execute_function(&program, &function, &user_inputs).unwrap();
```

It returns a tuple, where the first element is a map of all function variables (the hash map used to keep track of every register mentioned above) and the second element of the tuple is the proof of execution.

## Function variables map

As said before, this map stores the variables of the function that we are executing (constant, input, output, and intermediate registers). It is not the goal of this documentation to explain the syntax of Aleo programs (see [here](find the link in aleo.org)) but let's explain what these are with a toy example:

```aleo
function add_with_modulus_8:
    input r0 as u64.public;
    input r1 as u64.public;
    add r0 r1 into r2;
    mod r2 8u8 into r3;
    output r3 as u64.public;
```

This is not a very useful program but it is useful to see all the things mentioned before. On it, we can see some `input` definitions and an `output` definition. Let's focus on the registers (the keys of our variables map), we have `r0` and `r1` defined as input registers and `r3` as an output register. `r2` is what's called an *intermediate* register and `8u8` is a literal (constant) value. Literal values are stored in the index map with their value as key (in this case `8u8`).

To summarize, at the end of the execution the variables map should look like this

```json
{
    "r0": <value_provided_by_user>,
    "r1": <value_provided_by_user>,
    "r2": <result_of_r1_plus_r2>,
    "8u8": UInt8Gadget(8),
    "r3": <result_of_r2_mod_8>,
}
```

Let's focus now on how this map is built throught execution. This is separated in three stages: initialization, input processing and output processing.

For the first stage (initialization) the input, output, and constant registers are inserted. The first two with `None` as a value and the latter as a `Some` containing a constant gadget. This is done by the function `function_variables`. In `execute_function` this happens in this line:

```rust
let mut function_variables = helpers::function_variables(function, constraint_system.clone())?;
```

The input registers `None`s are replaced with input or witness gadgets depending on their visibility in the second stage (input processing). This is done by the function `process_inputs` of the `helpers.rs` module.

The output registers and all the intermediate registers are handled in the third and final stage (output processing). This is done by the function `process_outputs` of the `helpers.rs` module.

The three stages defined above are done by functions which take the `constraint_system` as input, as they need to mutate it. It might look like there's no mutation because the argument is not a mutable reference, but keep in mind our `constraint_system` is ultimately an `RC<Refcell>`.

An important thing to note about the operands process is that it requires a bit more work when the `record` data type is involved. This is because we need to keep track of all the record entries, so if a register is a record it's essentially a map with multiple entries. As an example, if there's a record declared like so

```aleo
record credits:
owner as address.private;
gates as u64.private;
```

and an input instruction

```aleo
input r0 as credits.record;
```

the map ends up like this

```json
{
    "r0.owner": <value_provided_by_user>,
    "r0.gates": <value_provided_by_user>
}
```

## Proof verification

Verifying a given proof amounts to the following function call

```rust
let result = vmtropy::verify_proof(function_verifying_key.clone(), public_inputs, proof).unwrap();
assert!(result);
```

Note that you have to provide the public inputs of the circuit, something the prover should have given to you along with the proof. Inputs are expected to be of type `UserInputValueType`, an enum that encapsulates all the possible types circuit inputs can have.

## Full example

Let's say we have the following Aleo program:

```aleo
program foo.aleo;

function main:
    input r0 as u64.public;
    input r1 as u64.public;
    add r0 r1 into r2;
    output r2 as u64.public;
```

Executing the function `main` would look like this:

```rust
use vmtropy::jaleo::UserInputValueType::U16;

fn main() {
    use vmtropy::{build_program, execute_function};

    // Parse the program
    let program_string = std::fs::read_to_string("./programs/add/main.aleo").unwrap();
    let (program, build) = build_program(&program_string).unwrap();
    let function = String::from("hello_1");
    // Declare the inputs (it is the same for public or private)
    let user_inputs = vec![U16(1), U16(1)];

    // Execute the function
    let (_function_variables, proof) = execute_function(&program, &function, &user_inputs).unwrap();
    let (_proving_key, verifying_key) = build.get(&function).unwrap();

    assert!(vmtropy::verify_proof(verifying_key.clone(), &user_inputs, &proof).unwrap())
}
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
