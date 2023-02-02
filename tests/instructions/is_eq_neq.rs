#[cfg(test)]
mod is_eq_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::Parser;
    use vmtropy::jaleo::{
        Program,
        UserInputValueType::{I8, U16, U32, U64, U8},
    };

    #[test]
    fn test_is_eq_with_u8_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            output r2 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u8", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u8_private_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_8:
            input r0 as u8.private;
            input r1 as u8.private;
            is.eq r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u8", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_9:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            output r2 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u8", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u16", "r4", "r2", "r3"];

        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_is_eq_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            is.eq r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u16", "r4", "r2", "r3"];
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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u16", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u32", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            is.eq r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u32", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u32", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u64", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            is.eq r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u64", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1u64", "r4", "r2", "r3"];

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
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_i8_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_13";

        /*
        function hello_13:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            output r2 as i8.public;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1i8", "r4", "r2", "r3"];

        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_i8_private_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_14";

        /*
        function hello_14:
            input r0 as i8.private;
            input r1 as i8.private;
            is.eq r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1i8", "r4", "r2", "r3"];

        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_is_eq_with_i8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("is_eq_neq").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_15";

        /*
        function hello_15:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "1i8", "r4", "r2", "r3"];

        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false".to_owned());
    }
}
