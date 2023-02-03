#[cfg(test)]
mod hash_psd2_tests {
    use crate::helpers::test_helpers;
    use lambdavm::jaleo::UserInputValueType::{U16, U32, U64, U8, I8};
    use snarkvm::prelude::{Parser, Program, Testnet3};

    #[test]
    fn test_hash_psd2_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_10:
            input r0 as u8.public;
            hash.psd2 r0 into r1;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_11:
            input r0 as u8.private;
            hash.psd2 r0 into r1;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_12:
            input r0 as u8.public;
            hash.psd2 r0 into r1;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            hash.psd2 r0 into r1;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_hash_psd2_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            hash.psd2 r0 into r1;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            hash.psd2 r0 into r1;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            hash.psd2 r0 into r1;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            hash.psd2 r0 into r1;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            hash.psd2 r0 into r1;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            hash.psd2 r0 into r1;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            hash.psd2 r0 into r1;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            hash.psd2 r0 into r1;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_i8_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_13";

        /*
        function hello_13:
            input r0 as i8.public;
            hash.psd2 r0 into r1;
            output r2 as i8.public;
        */

        let user_inputs = vec![I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_i8_private_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_14";

        /*
        function hello_14:
            input r0 as i8.private;
            hash.psd2 r0 into r1;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_hash_psd2_with_i8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("hash_psd2").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_15";

        /*
        function hello_15:
            input r0 as i8.public;
            hash.psd2 r0 into r1;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleField(_)));
        assert_ne!(r1.value().unwrap(), r0.value().unwrap());
    }
}
