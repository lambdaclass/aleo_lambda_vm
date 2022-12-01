#[cfg(test)]
mod credits_functions_tests {
    use ark_r1cs_std::R1CSVar;
    use simpleworks::types::value::SimpleworksValueType::{Address, Record, U64};
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use vmtropy::{build_program, circuit_io_type::CircuitIOType::SimpleRecord, verify_execution};

    fn address(n: u64) -> (String, [u8; 63]) {
        let mut address_bytes = [0_u8; 63];
        let address_string =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_string, address_bytes)
    }

    #[test]
    fn test_genesis() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("genesis").unwrap())
            .unwrap();

        let (address_string, address_bytes) = address(0);

        let user_inputs = vec![Address(address_bytes), U64(1)];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_output_register_locator = &"r2".to_string();

        assert!(circuit_outputs.len() == 1);
        if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
            assert_eq!(output_register_locator, expected_output_register_locator);
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 1);
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.get("genesis").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }

    #[test]
    fn test_mint() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("mint").unwrap())
            .unwrap();

        let (address_string, address_bytes) = address(0);

        let user_inputs = vec![Address(address_bytes), U64(1)];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_output_register_locator = &"r2".to_string();

        assert!(circuit_outputs.len() == 1);
        if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
            assert_eq!(output_register_locator, expected_output_register_locator);
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 1);
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.get("mint").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }

    #[test]
    fn test_transfer() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("transfer").unwrap())
            .unwrap();

        let (sender_address_string, sender_address_bytes) = address(0);
        let amount_to_transfer = 1_u64;
        let (receiver_address_string, receiver_address_bytes) = address(0);

        let user_inputs = vec![
            Record(sender_address_bytes, amount_to_transfer),
            Address(receiver_address_bytes),
            U64(amount_to_transfer),
        ];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        let receiver_record_output_register = &"r4".to_string();
        let sender_record_output_register = &"r5".to_string();

        assert_eq!(circuit_outputs.len(), 2);

        let mut circuit_outputs = circuit_outputs.iter();

        // The first output is the resulting record of the receiver.
        if let Some((output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
            assert_eq!(output_register_locator, receiver_record_output_register);
            assert_eq!(
                record.owner.value().unwrap(),
                receiver_address_string,
                "Receiver address is incorrect"
            );
            assert_eq!(
                record.gates.value().unwrap(),
                amount_to_transfer,
                "Receiver amount is incorrect"
            );
        }

        // The second output is the resulting record of the sender.
        if let Some((output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
            assert_eq!(output_register_locator, sender_record_output_register);
            assert_eq!(
                record.owner.value().unwrap(),
                sender_address_string,
                "Sender address is incorrect"
            );
            assert_eq!(
                record.gates.value().unwrap(),
                0,
                "Sender gates is incorrect"
            );
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.get("transfer").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }

    #[test]
    fn test_combine() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("combine").unwrap())
            .unwrap();

        let (address_string, address_bytes) = address(0);
        let amount = 1_u64;

        let user_inputs = vec![Record(address_bytes, amount), Record(address_bytes, amount)];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_output_register_locator = &"r3".to_string();

        assert_eq!(circuit_outputs.len(), 1);
        if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
            assert_eq!(output_register_locator, expected_output_register_locator);
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), amount * 2);
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.get("combine").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }

    #[test]
    fn test_split() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("split").unwrap())
            .unwrap();

        let (address_string, address_bytes) = address(0);
        let gates_of_existing_record = 2_u64;
        let gates_for_new_record = 1_u64;

        let user_inputs = vec![
            Record(address_bytes, gates_of_existing_record),
            U64(gates_for_new_record),
        ];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        assert_eq!(circuit_outputs.len(), 2, "Two output records were expected");

        let mut circuit_outputs = circuit_outputs.iter();

        // The first output is new record.
        if let Some((_output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
            assert_eq!(
                record.owner.value().unwrap(),
                address_string,
                "Owner address is incorrect"
            );
            assert_eq!(
                record.gates.value().unwrap(),
                gates_for_new_record,
                "Record amount is incorrect"
            );
        }

        // The second output is the splitted record.
        if let Some((_output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
            assert_eq!(
                record.owner.value().unwrap(),
                address_string,
                "Owner address is incorrect"
            );
            assert_eq!(
                record.gates.value().unwrap(),
                gates_of_existing_record - gates_for_new_record,
                "Record gates is incorrect"
            );
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.get("split").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }

    #[test]
    fn test_fee() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("fee").unwrap())
            .unwrap();

        let (address_string, address_bytes) = address(0);
        let amount = 1_u64;
        let fee = 1_u64;

        let user_inputs = vec![Record(address_bytes, amount), U64(fee)];

        let (circuit_outputs, proof) = vmtropy::execute_function(&function, &user_inputs).unwrap();

        assert_eq!(circuit_outputs.len(), 1, "One output records was expected");

        if let Some((_output_register_locator, SimpleRecord(record))) =
            circuit_outputs.iter().next()
        {
            assert_eq!(
                record.owner.value().unwrap(),
                address_string,
                "Owner address is incorrect"
            );
            assert_eq!(
                record.gates.value().unwrap(),
                amount - fee,
                "Record amount is incorrect"
            );
        }

        let rng = &mut ark_std::test_rng();
        let program_build = build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.get("fee").unwrap();
        let public_inputs = [];
        assert!(
            verify_execution(function_verifying_key.clone(), &public_inputs, proof, rng).unwrap()
        )
    }
}
