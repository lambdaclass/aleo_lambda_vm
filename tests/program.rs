#[cfg(test)]
mod tests {
    use anyhow::Result;
    use simpleworks::types::value::{
        RecordEntriesMap,
        SimpleworksValueType::{Record, U16, U32, U64},
    };
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use vmtropy::{build_program, verify_proof};

    fn read_add_program(instruction: &str) -> Result<String> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(&format!("programs/{instruction}/main.aleo"));
        let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        Ok(program)
    }

    #[test]
    fn test01_add_with_u16_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
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
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        assert!(verify_proof(function_verifying_key.clone(), &user_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test02_add_with_u16_private_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        println!("{}", function);
        println!("{:?}", user_inputs);

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test03_add_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test04_add_with_u32_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test05_add_with_u32_private_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test06_add_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test07_add_with_u64_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test08_add_with_u64_private_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test09_add_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "2u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u16_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
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
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u16_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u16".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u32_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u32_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u32".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u64_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u64_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_subtract_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let rng = &mut ark_std::test_rng();
        let (circuit_outputs, proof) =
            vmtropy::execute_function(&function, &user_inputs, rng).unwrap();

        assert_eq!(
            circuit_outputs.values().next().unwrap().to_string(),
            "0u64".to_owned()
        );

        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get(function_name).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof, rng).unwrap())
    }

    #[test]
    fn test_record_add() {
        let program_string = read_add_program("record").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        let mut address = [0_u8; 63];
        let address_string = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh";
        for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }

        let user_inputs = vec![
            Record {
                owner: address,
                gates: 0,
                entries: RecordEntriesMap::default(),
            },
            U64(1),
        ];

        // execute circuit
        let (circuit_outputs, _bytes_proof) = vmtropy::execute_function(
            &function,
            &user_inputs,
            &mut simpleworks::marlin::generate_rand(),
        )
        .unwrap();

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output);
        }
    }

    #[test]
    fn test_record_subtract() {
        let program_string = read_add_program("record").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        let mut address = [0_u8; 63];
        let address_string = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh";
        for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }

        let user_inputs = vec![
            Record {
                owner: address,
                gates: 1,
                entries: RecordEntriesMap::default(),
            },
            U64(1),
        ];

        // execute circuit
        let (circuit_outputs, _bytes_proof) = vmtropy::execute_function(
            &function,
            &user_inputs,
            &mut simpleworks::marlin::generate_rand(),
        )
        .unwrap();

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output);
        }
    }
}
