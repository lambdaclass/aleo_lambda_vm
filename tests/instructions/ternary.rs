#[cfg(test)]
mod ternary_tests {
    use crate::helpers::test_helpers;
    use lambdavm::jaleo::{
        Program,
        UserInputValueType::{I8, U16, U32, U64, U8},
    };
    use snarkvm::prelude::Parser;

    #[test]
    fn test_ternary_with_u8_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());
    }

    #[test]
    fn test_ternary_with_u8_private_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_8:
            input r0 as u8.private;
            input r1 as u8.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u8_private_and_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_9:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u16_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_ternary_with_u16_private_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u16_private_and_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_private_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_private_and_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_private_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_private_and_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_i8_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_13";

        /*
        function hello_13:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            outputr32 as i8.public;
        */

        let user_inputs = vec![I8(1), I8(1)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());
    }

    #[test]
    fn test_ternary_with_i8_private_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_14";

        /*
        function hello_14:
            input r0 as i8.private;
            input r1 as i8.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_i8_private_and_public_inputs_true_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_15";

        /*
        function hello_15:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "1".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "true".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r3.value().unwrap(), r0.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u8_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_7:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            outputr32 as u8.public;
        */

        let user_inputs = vec![U8(1), U8(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_ternary_with_u8_private_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_8:
            input r0 as u8.private;
            input r1 as u8.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u8_private_and_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_9:
            input r0 as u8.public;
            input r1 as u8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u8.private;
        */

        let user_inputs = vec![U8(1), U8(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u16_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(2)];

        // execute circuit
        let (function_variables, _proof) =
            lambdavm::execute_function(&program, function_name, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }
    }

    #[test]
    fn test_ternary_with_u16_private_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u16.private;
        */

        let user_inputs = vec![U16(1), U16(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u16_private_and_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u16.private;
        */

        let user_inputs = vec![U16(1), U16(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_private_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u32.private;
        */

        let user_inputs = vec![U32(1), U32(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u32_private_and_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u32.private;
        */

        let user_inputs = vec![U32(1), U32(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_private_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u64.private;
        */

        let user_inputs = vec![U64(1), U64(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_u64_private_and_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output rr3as u64.private;
        */

        let user_inputs = vec![U64(1), U64(2)];

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
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_i8_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_13";

        /*
        function hello_13:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            outputr32 as i8.public;
        */

        let user_inputs = vec![I8(1), I8(2)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());
    }

    #[test]
    fn test_ternary_with_i8_private_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_14";

        /*
        function hello_14:
            input r0 as i8.private;
            input r1 as i8.private;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(2)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }

    #[test]
    fn test_ternary_with_i8_private_and_public_inputs_false_value() {
        let program_string = test_helpers::read_program("ternary").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_15";

        /*
        function hello_15:
            input r0 as i8.public;
            input r1 as i8.public;
            is.eq r0 r1 into r2;
            ternary r2 r0 r1 into r3;
            output r3 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(2)];

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
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r0.value().unwrap(), "1".to_owned());

        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r1.value().unwrap(), "2".to_owned());

        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false".to_owned());

        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, lambdavm::CircuitIOType::SimpleInt8(_)));
        assert_eq!(r3.value().unwrap(), r1.value().unwrap());
    }
}
