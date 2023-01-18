#[cfg(test)]
mod gt_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::Parser;
    use vmtropy::jaleo::{
        Program, Record as JAleoRecord, RecordEntriesMap,
        UserInputValueType::{Record, U16, U32, U64},
    };

    #[test]
    fn compare_with_u16_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_1";

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u16_private_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_2";

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u16_private_and_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_3";

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u32_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_4";

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u32_private_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_5";

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u32_private_and_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_6";

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u64_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_7";

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u64_private_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_8";

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn compare_with_u64_private_and_public_inputs() {
        let program_string = test_helpers::read_program("compare").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
        let function_name = "hello_9";

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            [compare-functions] r0 r1 into r2/r3/r4/r5;
            output r2/r3/r4/r5 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (_compiled_function_variables, _proof) =
            vmtropy::execute_function(&program, function_name, &user_inputs).unwrap();
    }

    #[test]
    fn test_record_add() {
        let program_string = test_helpers::read_program("record").unwrap();
        let (_, program) = Program::parse(&program_string).unwrap();
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
    }
}
