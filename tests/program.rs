mod helpers;

#[cfg(test)]
mod tests {
    use super::helpers::test_helpers;
    use anyhow::Result;
    use ark_r1cs_std::R1CSVar;
    use simpleworks::gadgets::ConstraintF;
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use std::str::FromStr;
    use vmtropy::{
        build_program,
        jaleo::{
            self, Record as JAleoRecord, RecordEntriesMap,
            UserInputValueType::{Record, U16, U32, U64},
        },
        verify_proof,
    };

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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        assert!(verify_proof(function_verifying_key.clone(), &user_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "2u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u16".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u32".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = [];
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
        let (_compiled_function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // assert_eq!(
        //     circuit_outputs.values().next().unwrap().to_string(),
        //     "0u64".to_owned()
        // );

        let (_program, program_build) = build_program(&program_string).unwrap();
        let function_identifier = Identifier::from_str(function_name).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get(&function_identifier).unwrap();
        let public_inputs = user_inputs;
        assert!(verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap())
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
            Record(JAleoRecord {
                owner: address,
                gates: 0,
                data: RecordEntriesMap::default(),
                nonce: ConstraintF::default(),
            }),
            U64(1),
        ];

        // execute circuit
        let (_compiled_function_variables, _bytes_proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // for (register, output) in circuit_outputs {
        //     println!("{}: {:?}", register, output);
        // }
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
            Record(JAleoRecord {
                owner: address,
                gates: 1,
                data: RecordEntriesMap::default(),
                nonce: ConstraintF::default(),
            }),
            U64(1),
        ];

        // execute circuit
        let (_compiled_function_variables, _bytes_proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        // for (register, output) in circuit_outputs {
        //     println!("{}: {:?}", register, output);
        // }
    }

    #[test]
    fn test_cast_custom_record() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/token.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("mint").unwrap())
            .unwrap();

        let (address_string, address_bytes) = test_helpers::address(0);
        let amount_to_mint = 1_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::U64(amount_to_mint),
            jaleo::UserInputValueType::Address(address_bytes),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "0u64", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Amount to mint.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), amount_to_mint.to_string());

        // Address.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), address_string);

        // Constant literal (record gates).
        let constant_0u64 = function_variables["0u64"].as_ref().unwrap();
        assert!(matches!(
            constant_0u64,
            vmtropy::CircuitIOType::SimpleUInt64(_)
        ));
        assert_eq!(constant_0u64.value().unwrap(), "0".to_owned());

        // Minted output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r2 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 0);
            assert_ne!(record.nonce, ConstraintF::default());
        } else {
            panic!("r2 should be a record");
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build
            .map
            .get(&Identifier::try_from("mint").unwrap())
            .unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
        )
    }
}
