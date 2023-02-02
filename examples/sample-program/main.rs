use lambdavm::jaleo::UserInputValueType::U16;

fn main() {
    use lambdavm::{build_program, execute_function};

    // Parse the program
    let program_string = std::fs::read_to_string("./programs/add/main.aleo").unwrap();
    let (program, build) = build_program(&program_string).unwrap();
    let function = String::from("hello_1");
    // Declare the inputs (it is the same for public or private)
    let user_inputs = vec![U16(1), U16(1)];

    // Execute the function
    let (_function_variables, proof) = execute_function(&program, &function, &user_inputs).unwrap();
    let (_proving_key, verifying_key) = build.get(&function).unwrap();

    assert!(lambdavm::verify_proof(verifying_key.clone(), &user_inputs, &proof).unwrap())
}
