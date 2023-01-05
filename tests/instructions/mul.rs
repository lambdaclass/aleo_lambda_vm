#[cfg(test)]
mod mul_tests {
    use crate::helpers::test_helpers;
    use ark_r1cs_std::R1CSVar;
    use simpleworks::gadgets::ConstraintF;
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use vmtropy::jaleo::{
        self, Record as JAleoRecord, RecordEntriesMap,
        UserInputValueType::{Record, U16, U32, U64, U8},
    };

    #[test]
    fn test_record_subtract() {
        let program_string = test_helpers::read_program("record").unwrap();
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
        let (_compiled_function_variables, _proof) =
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

        let (function_variables, _proof) =
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
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &_proof).unwrap()
        )
    }

    #[test]
    fn test_mul_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
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
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_11";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_8:
            input r0 as u8.private;
            input r1 as u8.private;
            mul r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_12";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_9:
            input r0 as u8.public;
            input r1 as u8.public;
            mul r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            mul r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_mul_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            mul r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            mul r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            mul r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            mul r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            mul r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            mul r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            mul r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_mul_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("mul").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            mul r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }
}
