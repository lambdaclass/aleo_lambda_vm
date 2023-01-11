mod helpers;

#[cfg(test)]
mod marlin_tests {
    use super::helpers::test_helpers;
    use snarkvm::prelude::Parser;
    use std::str::FromStr;
    use vmtropy::{
        build_program,
        jaleo::{
            Identifier, Program,
            UserInputValueType::{U16, U8},
        },
        verify_proof,
    };

    #[test]
    fn test_add() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();
        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        assert!(verify_proof(function_verifying_key.clone(), &user_inputs, &proof).unwrap())
    }

    #[test]
    fn test_subtract() {
        let program_string = test_helpers::read_program("subtract").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
    }

    #[test]
    fn test_is_eq() {
        let program_string = test_helpers::read_program("is_eq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
    }

    #[test]
    fn test_mul() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            mul r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
    }

    #[test]
    fn test_ternary() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            outputr32 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
    }
}
