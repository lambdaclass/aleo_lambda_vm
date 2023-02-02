#[cfg(test)]
mod add_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::Parser;
    use vmtropy::jaleo::{
        Program,
        UserInputValueType::{I8, U16, U32, U64},
    };

    #[test]
    fn test_add_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_i8_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_10";

        /*
        function hello_7:
            input r0 as i8.public;
            input r1 as i8.public;
            add r0 r1 into r2;
            output r2 as i8.public;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_i8_private_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_11";

        /*
        function hello_2:
            input r0 as i8.private;
            input r1 as i8.private;
            add r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_add_with_i8_private_and_public_inputs() {
        let program_string = test_helpers::read_program("add").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_12";

        /*
        function hello_3:
            input r0 as i8.public;
            input r1 as i8.public;
            add r0 r1 into r2;
            output r2 as i8.private;
        */

        let user_inputs = vec![I8(1), I8(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }
}
