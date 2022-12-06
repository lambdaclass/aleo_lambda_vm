use ark_serialize::CanonicalSerialize;
use simpleworks::types::value::SimpleworksValueType::U32;
use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};

fn main() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples/sample-program/sample.aleo");
    let program_string = std::fs::read_to_string(path).unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello").unwrap())
        .unwrap();

    let user_inputs = vec![U32(2), U32(1)];

    // Run the `hello` function defined in the `sample.aleo` program
    let (outputs, proof) = vmtropy::execute_function(
        &function,
        &user_inputs,
        &mut simpleworks::marlin::generate_rand(),
    )
    .unwrap();

    for (register, value) in outputs {
        println!(
            "Output register {} has value {}",
            register,
            value.value().unwrap()
        );
    }

    let mut bytes_proof = Vec::new();
    match proof.serialize(&mut bytes_proof) {
        Ok(_) => println!("Proof of execution: \n0x{}", hex::encode(bytes_proof)),
        Err(_) => println!("⚠️ Error serializing proof"),
    }
}
