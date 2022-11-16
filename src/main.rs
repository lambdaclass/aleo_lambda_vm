use anyhow::Result;
use ark_r1cs_std::{prelude::AllocVar, uint32::UInt32, R1CSVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace};
use snarkvm::{
    circuit::IndexMap,
    prelude::{
        Function, Identifier, LiteralType, Opcode, Parser, PlaintextType, Program, Testnet3,
        ValueType,
    },
};

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

// TODO: Move these imports and the Marlin API in general to simpleworks
use ark_bls12_381::{Bls12_381, Fr};
use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
type MarlinInst = Marlin<Fr, MultiPC, FS>;
use ark_serialize::CanonicalSerialize;

fn main() {
    // Open a file
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/main.aleo");
    let program_string = std::fs::read_to_string(path).unwrap();
    // Parse Aleo Program
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();

    // Retrieve hello function.
    let hello_function = program.get_function(&Identifier::try_from("hello").unwrap()).unwrap();

    // Now we create a constraint system and the circuit that will verify
    // the signature, but we'll send a bad message.
    let cs = ConstraintSystem::<ConstraintF>::new_ref();
    // Here we map the parse inputs to circuit inputs.
    let circuit_inputs = circuit_inputs(hello_function.clone(), cs.clone()).unwrap();
    // Here we map the parse inputs to circuit outputs.
    let circuit_outputs = circuit_outputs(hello_function, circuit_inputs).unwrap();

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }

    assert!(cs.is_satisfied().unwrap());

    let mut rng = ark_std::test_rng();
    let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, &mut rng).unwrap();

    // Now, try to generate the verifying key and proving key with Marlin
    let (index_proving_key, index_verifying_key) =
        MarlinInst::index_from_constraint_system(&universal_srs, cs.clone()).unwrap();

    let proof = MarlinInst::prove_from_constraint_system(&index_proving_key, cs, &mut rng).unwrap();

    assert!(MarlinInst::verify(&index_verifying_key, &[], &proof, &mut rng).unwrap());

    let mut bytes = Vec::new();
    proof.serialize(&mut bytes).unwrap();
    println!("Proof bytes: {:?}", bytes);
}

// TODO: The input values and the function result type are hardcoded.
fn circuit_inputs(
    function: Function<Testnet3>,
    cs: ConstraintSystemRef<ConstraintF>,
) -> Result<IndexMap<String, UInt32<ConstraintF>>> {
    let mut circuit_inputs = IndexMap::new();
    for input in function.inputs() {
        let register = input.register();
        let circuit_input = match input.value_type() {
            ValueType::Constant(_) => todo!(),
            ValueType::Public(PlaintextType::Literal(LiteralType::U32)) => {
                UInt32::new_input(Namespace::new(cs.clone(), None), || Ok(0))?
            }
            ValueType::Public(PlaintextType::Literal(_)) => todo!(),
            ValueType::Public(_) => todo!(),
            ValueType::Private(PlaintextType::Literal(LiteralType::U32)) => {
                UInt32::new_witness(Namespace::new(cs.clone(), None), || Ok(0))?
            }
            ValueType::Private(PlaintextType::Literal(_)) => todo!(),
            ValueType::Private(_) => todo!(),
            ValueType::Record(_) => todo!(),
            ValueType::ExternalRecord(_) => todo!(),
        };
        circuit_inputs.insert(register.to_string(), circuit_input);
    }
    Ok(circuit_inputs)
}

// TODO: The circuit_inputs and the function result types are hardcoded to
// we could use a generic type here because we except different value types.
fn circuit_outputs(
    function: Function<Testnet3>,
    circuit_inputs: IndexMap<String, UInt32<ConstraintF>>,
) -> Result<IndexMap<String, UInt32<ConstraintF>>> {
    let mut circuit_outputs = IndexMap::new();
    for instruction in function.instructions() {
        let instruction_operands = instruction
            .operands()
            .iter()
            .map(|o| match circuit_inputs.get(&o.to_string()) {
                Some(circuit_input) => circuit_input.clone(),
                None => todo!(),
            })
            .collect::<Vec<_>>();

        let circuit_output = match instruction.opcode() {
            Opcode::Assert(_) => todo!(),
            Opcode::Call => todo!(),
            Opcode::Cast => todo!(),
            Opcode::Command(_) => todo!(),
            Opcode::Commit(_) => todo!(),
            Opcode::Finalize(_) => todo!(),
            Opcode::Hash(_) => todo!(),
            Opcode::Is(_) => todo!(),
            Opcode::Literal("add") => {
                UInt32::<ConstraintF>::addmany(instruction_operands.as_slice())?
            }
            Opcode::Literal(_) => todo!(),
        };
        // TODO: Destinations should be handled better.
        circuit_outputs.insert(instruction.destinations()[0].to_string(), circuit_output);
    }
    Ok(circuit_outputs)
}
