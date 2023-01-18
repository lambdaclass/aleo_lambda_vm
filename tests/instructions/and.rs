#[cfg(test)]
mod and_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use vmtropy::jaleo::UserInputValueType::{Boolean, U16, U32, U64, U8};

    #[test]
    fn test_and_with_bool_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_1:
            input r0 as boolean.public;
            input r1 as boolean.public;
            and r0 r1 into r2;
            output r2 as boolean.public;
        */

        let user_inputs = vec![Boolean(true), Boolean(true)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "true".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "true".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());
    }

    #[test]
    fn test_and_with_bool_private_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_2:
            input r0 as boolean.private;
            input r1 as boolean.private;
            and r0 r1 into r2;
            output r2 as boolean.private;
        */

        let user_inputs = vec![Boolean(false), Boolean(false)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "false".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "false".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_and_with_bool_private_and_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_3:
            input r0 as boolean.public;
            input r1 as boolean.public;
            and r0 r1 into r2;
            output r2 as boolean.private;
        */

        let user_inputs = vec![Boolean(true), Boolean(false)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "true".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "false".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_and_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_4:
            input r0 as u8.public;
            input r1 as u8.public;
            and r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(6), U8(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_5:
            input r0 as u8.private;
            input r1 as u8.private;
            and r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(6), U8(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_6:
            input r0 as u8.public;
            input r1 as u8.public;
            and r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(6), U8(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_7:
            input r0 as u16.public;
            input r1 as u16.public;
            and r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(6), U16(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_8:
            input r0 as u16.private;
            input r1 as u16.private;
            and r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(6), U16(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_9:
            input r0 as u16.public;
            input r1 as u16.public;
            and r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(6), U16(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_10";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_10:
            input r0 as u32.public;
            input r1 as u32.public;
            and r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(6), U32(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_11";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_11:
            input r0 as u32.private;
            input r1 as u32.private;
            and r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(6), U32(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_12";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_12:
            input r0 as u32.public;
            input r1 as u32.public;
            and r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(6), U32(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_13";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_13:
            input r0 as u64.public;
            input r1 as u64.public;
            and r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(6), U64(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_14";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_14:
            input r0 as u64.private;
            input r1 as u64.private;
            and r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(6), U64(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }

    #[test]
    fn test_and_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("and").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_15";
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        /*
        function hello_15:
            input r0 as u64.public;
            input r1 as u64.public;
            and r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(6), U64(3)];

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
        assert_eq!(r0.value().unwrap(), "6".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "3".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "2".to_owned());
    }
}