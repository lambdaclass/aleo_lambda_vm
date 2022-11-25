#[cfg(test)]
mod tests {
    use anyhow::Result;
    use simpleworks::types::value::SimpleworksValueType::{U128, U16, U32, U64};
    fn read_add_program(instruction: &str) -> Result<String> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(&format!("programs/{instruction}/main.aleo"));
        let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        Ok(program)
    }

    #[test]
    fn test01_add_with_u16_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(&program_string, "hello_1", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test02_add_with_u16_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test03_add_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_3", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test04_add_with_u32_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_4", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test05_add_with_u32_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_5", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test06_add_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_6", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test07_add_with_u64_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_7", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test08_add_with_u64_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_8", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test09_add_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_9", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test10_add_with_u128_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_10:
            input r0 as u128.public;
            input r1 as u128.public;
            add r0 r1 into r2;
            output r2 as u128.public;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_10", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test11_add_with_u128_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_11:
            input r0 as u128.private;
            input r1 as u128.private;
            add r0 r1 into r2;
            output r2 as u128.private;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_11", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test12_add_with_u128_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        /*
        function hello_12:
            input r0 as u128.public;
            input r1 as u128.public;
            add r0 r1 into r2;
            output r2 as u128.private;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_12", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_1:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.public;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(&program_string, "hello_1", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_2:
            input r0 as u16.private;
            input r1 as u16.private;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_3:
            input r0 as u16.public;
            input r1 as u16.public;
            add r0 r1 into r2;
            output r2 as u16.private;
        */

        let user_inputs = vec![U16(1), U16(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_3", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_4:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.public;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_4", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_5:
            input r0 as u32.private;
            input r1 as u32.private;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_5", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_6:
            input r0 as u32.public;
            input r1 as u32.public;
            add r0 r1 into r2;
            output r2 as u32.private;
        */

        let user_inputs = vec![U32(1), U32(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_6", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_7:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.public;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_7", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_8:
            input r0 as u64.private;
            input r1 as u64.private;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_8", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_9:
            input r0 as u64.public;
            input r1 as u64.public;
            add r0 r1 into r2;
            output r2 as u64.private;
        */

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_9", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_10:
            input r0 as u128.public;
            input r1 as u128.public;
            add r0 r1 into r2;
            output r2 as u128.public;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_10", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_11:
            input r0 as u128.private;
            input r1 as u128.private;
            add r0 r1 into r2;
            output r2 as u128.private;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_11", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        /*
        function hello_12:
            input r0 as u128.public;
            input r1 as u128.public;
            add r0 r1 into r2;
            output r2 as u128.private;
        */

        let user_inputs = vec![U128(1), U128(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_12", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_record_add() {
        let program_string = read_add_program("record").unwrap();

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_1", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_record_subtract() {
        let program_string = read_add_program("record").unwrap();

        let user_inputs = vec![U64(1), U64(1)];

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2", &user_inputs).unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }
}
