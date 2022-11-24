#[cfg(test)]
mod tests {
    use anyhow::Result;
    fn read_add_program(instruction: &str) -> Result<String> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(&format!("programs/{instruction}/main.aleo"));
        let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        Ok(program)
    }

    #[test]
    fn test01_add_with_u16_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(&program_string, "hello_1").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test02_add_with_u16_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test03_add_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_3").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test04_add_with_u32_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_4").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test05_add_with_u32_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_5").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test06_add_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_6").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test07_add_with_u64_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_7").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test08_add_with_u64_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_8").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test09_add_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_9").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test10_add_with_u128_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_10").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test11_add_with_u128_private_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_11").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test12_add_with_u128_private_and_public_inputs() {
        let program_string = read_add_program("add").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_12").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(&program_string, "hello_1").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u16_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_3").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_4").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_5").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u32_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_6").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_7").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_8").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_subtract_with_u64_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_9").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_10").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_private_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_11").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test_subtract_with_u128_private_and_public_inputs() {
        let program_string = read_add_program("subtract").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_12").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_record_add() {
        let program_string = read_add_program("record").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_1").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test_record_subtract() {
        let program_string = read_add_program("record").unwrap();

        // execute circuit
        let (ret_ok, circuit_outputs, _bytes_proof) =
            vmtropy::execute_function(program_string.as_str(), "hello_2").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }
}
