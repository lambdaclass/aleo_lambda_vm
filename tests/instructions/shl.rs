#[cfg(test)]
mod shl_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::{Parser, Program, Testnet3};
    use vmtropy::jaleo::UserInputValueType::{U16, U32, U64, U8};

    #[test]
    fn test_shl_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            shl r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_8:
            input r0 as u8.private;
            input r1 as u8.private;
            shl r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_9:
            input r0 as u8.public;
            input r1 as u8.public;
            shl r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            shl r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_shl_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            shl r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            shl r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            shl r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            shl r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            shl r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            shl r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            shl r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_shl_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("shl").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            shl r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

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
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }
}
