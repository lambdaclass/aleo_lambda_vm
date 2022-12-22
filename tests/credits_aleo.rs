mod helpers;

#[cfg(test)]
mod credits_functions_tests {
    use crate::helpers::test_helpers::{self, vm_record_entries_are_equal};
    use ark_r1cs_std::R1CSVar;
    use simpleworks::gadgets::ConstraintF;
    use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
    use vmtropy::{jaleo, VMRecordEntriesMap};

    #[test]
    fn test_genesis() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("genesis").unwrap())
            .unwrap();

        let (address_string, address_bytes) = test_helpers::address(0);
        let genesis_credits = 1_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::Address(address_bytes),
            jaleo::UserInputValueType::U64(genesis_credits),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Address.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r0.value().unwrap(), address_string);

        // Genesis credits.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), genesis_credits.to_string());

        // Genesis output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), genesis_credits);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, ConstraintF::default());
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get("genesis").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
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

        let (address_string, address_bytes) = test_helpers::address(0);
        let credits_to_mint = 1_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::Address(address_bytes),
            jaleo::UserInputValueType::U64(credits_to_mint),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Address.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r0.value().unwrap(), address_string);

        // Credits to mint.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), credits_to_mint.to_string());

        // Minted output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), credits_to_mint);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, ConstraintF::default());
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get("mint").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
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

        let (sender_address_string, sender_address_bytes) = test_helpers::address(0);
        let initial_balance = 1_u64;
        let amount_to_transfer = initial_balance;
        let (receiver_address_string, receiver_address_bytes) = test_helpers::address(0);

        let user_inputs = vec![
            test_helpers::input_record(
                sender_address_bytes,
                initial_balance,
                jaleo::RecordEntriesMap::default(),
                ConstraintF::default(),
            ),
            jaleo::UserInputValueType::Address(receiver_address_bytes),
            jaleo::UserInputValueType::U64(amount_to_transfer),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_function_variables =
            vec!["r0", "r1", "r2", "r0.gates", "r3", "r0.owner", "r4", "r5"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Sender's input record.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), sender_address_string);
            assert_eq!(record.gates.value().unwrap(), initial_balance);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_eq!(record.nonce, ConstraintF::default());
        }

        // Receiver's address.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), receiver_address_string);

        // Amount to transfer.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), amount_to_transfer.to_string());

        // Sender's record gates.
        let r0_gates = function_variables["r0.gates"].as_ref().unwrap();
        assert!(matches!(r0_gates, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0_gates.value().unwrap(), initial_balance.to_string());

        // Sender's new balance.
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r3.value().unwrap(),
            (initial_balance - amount_to_transfer).to_string()
        );

        // Sender's address.
        let r0_owner = function_variables["r0.owner"].as_ref().unwrap();
        assert!(matches!(r0_owner, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), sender_address_string);

        // Receiver's output record.
        let r4 = function_variables["r4"].as_ref().unwrap();
        assert!(matches!(r4, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r4 {
            assert_eq!(record.owner.value().unwrap(), receiver_address_string);
            assert_eq!(record.gates.value().unwrap(), amount_to_transfer);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, ConstraintF::default());
        }

        // Sender's output record.
        let r5 = function_variables["r5"].as_ref().unwrap();
        assert!(matches!(r5, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r5 {
            assert_eq!(record.owner.value().unwrap(), sender_address_string);
            assert_eq!(
                record.gates.value().unwrap(),
                initial_balance - amount_to_transfer
            );
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, ConstraintF::default());
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get("transfer").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
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

        let (address_string, address_bytes) = test_helpers::address(0);
        let initial_balance = 1_u64;

        let first_record_nonce = test_helpers::sample_nonce();
        let second_record_nonce = test_helpers::sample_nonce();

        let user_inputs = vec![
            test_helpers::input_record(
                address_bytes,
                initial_balance,
                jaleo::RecordEntriesMap::default(),
                first_record_nonce,
            ),
            test_helpers::input_record(
                address_bytes,
                initial_balance,
                jaleo::RecordEntriesMap::default(),
                second_record_nonce,
            ),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_function_variables =
            vec!["r0", "r1", "r0.gates", "r1.gates", "r2", "r0.owner", "r3"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // First input record.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), initial_balance);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_eq!(record.nonce, first_record_nonce);
        }

        // Second input record.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r1 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), initial_balance);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_eq!(record.nonce, second_record_nonce);
        }

        // First record gates.
        let r0_gates = function_variables["r0.gates"].as_ref().unwrap();
        assert!(matches!(r0_gates, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0_gates.value().unwrap(), initial_balance.to_string());

        // Second record gates.
        let r1_gates = function_variables["r1.gates"].as_ref().unwrap();
        assert!(matches!(r1_gates, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1_gates.value().unwrap(), initial_balance.to_string());

        // Amount to transfer.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r2.value().unwrap(),
            (initial_balance + initial_balance).to_string()
        );

        // First record address.
        let r0_owner = function_variables["r0.owner"].as_ref().unwrap();
        assert!(matches!(r0_owner, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r0_owner.value().unwrap(), address_string);

        // Receiver's output record.
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r3 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(
                record.gates.value().unwrap(),
                initial_balance + initial_balance
            );
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, first_record_nonce);
            assert_ne!(record.nonce, second_record_nonce);
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get("combine").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
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

        let (address_string, address_bytes) = test_helpers::address(0);
        let gates_of_existing_record = 2_u64;
        let gates_for_new_record = 1_u64;
        let nonce = test_helpers::sample_nonce();

        let user_inputs = vec![
            test_helpers::input_record(
                address_bytes,
                gates_of_existing_record,
                jaleo::RecordEntriesMap::default(),
                nonce,
            ),
            jaleo::UserInputValueType::U64(gates_for_new_record),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        let expected_function_variables =
            vec!["r0", "r1", "r0.gates", "r2", "r0.owner", "r3", "r4"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Record to split.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), gates_of_existing_record);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_eq!(record.nonce, nonce);
        }

        // Amount to split.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), gates_for_new_record.to_string());

        // Record to split gates.
        let r0_gates = function_variables["r0.gates"].as_ref().unwrap();
        assert!(matches!(r0_gates, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r0_gates.value().unwrap(),
            gates_of_existing_record.to_string()
        );

        // Second new record balance.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r2.value().unwrap(),
            (gates_of_existing_record - gates_for_new_record).to_string()
        );

        // First new record.
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r3 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), gates_for_new_record);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, nonce);
        }

        // Second new record.
        let r4 = function_variables["r4"].as_ref().unwrap();
        assert!(matches!(r4, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r4 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(
                record.gates.value().unwrap(),
                gates_of_existing_record - gates_for_new_record
            );
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, nonce);
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) =
            program_build.map.get("split").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
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

        let (address_string, address_bytes) = test_helpers::address(0);
        let initial_balance = 1_u64;
        let fee = 1_u64;
        let nonce = test_helpers::sample_nonce();

        let user_inputs = vec![
            test_helpers::input_record(
                address_bytes,
                initial_balance,
                jaleo::RecordEntriesMap::default(),
                nonce,
            ),
            jaleo::UserInputValueType::U64(fee),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&function, &user_inputs).unwrap();

        // Input record.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), initial_balance);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_eq!(record.nonce, nonce);
        }

        // Fee.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), fee.to_string());

        // Output record balance.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r2.value().unwrap(), (initial_balance - fee).to_string());

        // Output record.
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r3 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), initial_balance - fee);
            assert!(vm_record_entries_are_equal(
                &record.entries,
                VMRecordEntriesMap::default()
            ));
            assert_ne!(record.nonce, nonce);
        }

        let (_program, program_build) = vmtropy::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build.map.get("fee").unwrap();
        let public_inputs = [];
        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), &public_inputs, &proof).unwrap()
        )
    }
}
