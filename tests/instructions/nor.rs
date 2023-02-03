#[cfg(test)]
mod nor_tests {
    use crate::helpers::test_helpers;
    use lambdavm::jaleo::UserInputValueType::{Boolean, I8, U16, U32, U64, U8};
    use snarkvm::prelude::{Parser, Program, Testnet3};

    #[test]
    fn test_nor_with_bool_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as boolean.public;
            input r1 as boolean.public;
            nor r0 r1 into r2;
            output r2 as boolean.public;
        */

        let user_inputs = vec![Boolean(true), Boolean(true)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "true".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "true".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_nor_with_bool_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as boolean.private;
            input r1 as boolean.private;
            nor r0 r1 into r2;
            output r2 as boolean.private;
        */

        let user_inputs = vec![Boolean(false), Boolean(false)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "false".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "false".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());
    }

    #[test]
    fn test_nor_with_bool_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as boolean.public;
            input r1 as boolean.public;
            nor r0 r1 into r2;
            output r2 as boolean.private;
        */

        let user_inputs = vec![Boolean(true), Boolean(false)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "true".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "false".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_nor_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u8.public;
            input r1 as u8.public;
            nor r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(170), U8(84)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "170".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u8.private;
            input r1 as u8.private;
            nor r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(170), U8(84)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "170".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u8_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u8.public;
            input r1 as u8.public;
            nor r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(170), U8(84)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r0.value().unwrap(), "170".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u16.public;
            input r1 as u16.public;
            nor r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(43690), U16(21844)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "43690".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "21844".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u16.private;
            input r1 as u16.private;
            nor r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(43690), U16(21844)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "43690".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "21844".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u16_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u16.public;
            input r1 as u16.public;
            nor r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(43690), U16(21844)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r0.value().unwrap(), "43690".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "21844".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_10:
            input r0 as u32.public;
            input r1 as u32.public;
            nor r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(2863311530), U32(1431655764)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "2863311530".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1431655764".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_11:
            input r0 as u32.private;
            input r1 as u32.private;
            nor r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(2863311530), U32(1431655764)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "2863311530".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1431655764".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u32_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_12:
            input r0 as u32.public;
            input r1 as u32.public;
            nor r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(2863311530), U32(1431655764)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "2863311530".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1431655764".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_13";

        /*
        function hello_13:
            input r0 as u64.public;
            input r1 as u64.public;
            nor r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(12297829382473034410), U64(6148914691236517204)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "12297829382473034410".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "6148914691236517204".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_14";

        /*
        function hello_14:
            input r0 as u64.private;
            input r1 as u64.private;
            nor r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(12297829382473034410), U64(6148914691236517204)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "12297829382473034410".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "6148914691236517204".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_u64_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_15";

        /*
        function hello_15:
            input r0 as u64.public;
            input r1 as u64.public;
            nor r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(12297829382473034410), U64(6148914691236517204)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), "12297829382473034410".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "6148914691236517204".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_i8_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_16";

        /*
        function hello_16:
            input r0 as i8.public;
            input r1 as i8.public;
            nor r0 r1 into r2;
            output r2 as i8.public;
        */

        let user_inputs = vec![I8(-86), I8(84)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "-86".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_i8_private_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_17";

        /*
        function hello_17:
            input r0 as i8.private;
            input r1 as i8.private;
            nor r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(-86), I8(84)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "-86".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }

    #[test]
    fn test_nor_with_i8_private_nor_public_inputs() {
        let program_string = test_helpers::read_program("nor").unwrap();
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function_name = "hello_18";

        /*
        function hello_18:
            input r0 as i8.public;
            input r1 as i8.public;
            nor r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(-86), I8(84)];

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
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "-86".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "84".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r2.value().unwrap(), "1".to_owned());
    }
}
