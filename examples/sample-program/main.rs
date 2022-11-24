fn main() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples/sample-program/sample.aleo");
    let program_string = std::fs::read_to_string(path).unwrap();

    let mut user_inputs = Vec::new();

    // Run the `hello` function defined in the `sample.aleo` program
    let (verifies, outputs, _proof) =
        vmtropy::execute_function(&program_string, "hello", &mut user_inputs).unwrap();
    assert!(verifies);

    for (register, value) in outputs {
        if let Ok(value) = value.value() {
            println!("Output register {} has value {}", register, value);
        } else {
            println!("⚠️ Error reading value from register {}", register);
        }
    }

    // TODO Add a proof generation step when it's merged
}
