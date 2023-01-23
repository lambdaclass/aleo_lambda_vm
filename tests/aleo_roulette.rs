mod helpers;

#[cfg(test)]
mod aleo_roulette_functions_tests {
    use crate::helpers::test_helpers;
    use ark_r1cs_std::R1CSVar;
    use simpleworks::marlin::MarlinProof;
    use snarkvm::prelude::{Function, Parser, Testnet3};
    use vmtropy::{
        helpers,
        jaleo::{self, Identifier, Program, UserInputValueType},
    };

    const ALEO_ROULETTE_PROGRAM_DIR: &str = "programs/aleo_roulette.aleo";
    const RECORDS_PROGRAM_DIR: &str = "programs/records.aleo";
    const PSD_HASH: &str = "psd_hash";
    const MAKE_BET: &str = "make_bet";
    const MINT_CASINO_TOKEN_RECORD: &str = "mint_casino_token_record";
    const PSD_BITS_MOD: &str = "psd_bits_mod";

    fn get_aleo_roulette_function(function_name: &str) -> (Program, Function<Testnet3>) {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(ALEO_ROULETTE_PROGRAM_DIR);
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        (program, function)
    }

    fn get_aleo_records_function(function_name: &str) -> (Program, Function<Testnet3>) {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(RECORDS_PROGRAM_DIR);
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        (program, function)
    }

    fn assert_that_proof_for_function_execution_is_correct(
        program: Program,
        public_inputs: &[UserInputValueType],
        proof: &MarlinProof,
        function_name: &str,
    ) {
        let (_program, program_build) = vmtropy::build_program(&program.to_string()).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build
            .map
            .get(&Identifier::try_from(function_name).unwrap())
            .unwrap();

        assert!(
            vmtropy::verify_proof(function_verifying_key.clone(), public_inputs, proof).unwrap()
        )
    }

    #[test]
    fn test_psd_hash() {
        let (program, function) = get_aleo_roulette_function(PSD_HASH);

        let user_inputs = [jaleo::UserInputValueType::U32(0_u32)];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Message to hash.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt32(_)));
        assert_eq!(r0.value().unwrap(), "0".to_owned());

        // Hashed output.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleField(_)));

        assert_that_proof_for_function_execution_is_correct(
            program,
            &user_inputs,
            &proof,
            PSD_HASH,
        );
    }

    #[test]
    fn test_mint_casino_token_record() {
        let (program, function) = get_aleo_roulette_function(MINT_CASINO_TOKEN_RECORD);

        let (address_string, address_bytes) = test_helpers::address(0);
        let amount_to_mint = 1_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::Address(address_bytes),
            jaleo::UserInputValueType::U64(amount_to_mint),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "0u64", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Amount to mint.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r0.value().unwrap(), address_string);

        // Address.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r1.value().unwrap(), amount_to_mint.to_string());

        // Constant literal (record gates).
        let constant_0u64 = function_variables["0u64"].as_ref().unwrap();
        assert!(matches!(
            constant_0u64,
            vmtropy::CircuitIOType::SimpleUInt64(_)
        ));
        assert_eq!(constant_0u64.value().unwrap(), "0".to_owned());

        // Minted output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r2 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 0);
            // assert_ne!(record.nonce, ConstraintF::default());
        } else {
            panic!("r2 should be a record");
        }

        assert_that_proof_for_function_execution_is_correct(
            program,
            &[],
            &proof,
            MINT_CASINO_TOKEN_RECORD,
        );
    }

    #[test]
    fn test_make_bet() {
        let (program, function) = get_aleo_roulette_function(MAKE_BET);

        let reward = 35_u64;

        let (casino_address_string, casino_address) = test_helpers::address(0);
        let casino_token_record_gates = 0_u64;
        let casino_token_record_amount = 100_u64;
        let mut casino_token_record_data = jaleo::RecordEntriesMap::new();
        casino_token_record_data.insert(
            "amount".to_owned(),
            vmtropy::jaleo::UserInputValueType::U64(casino_token_record_amount),
        );
        let casino_token_record_nonce = helpers::random_nonce();

        let casino_token_record = jaleo::Record {
            owner: casino_address,
            gates: casino_token_record_gates,
            data: casino_token_record_data,
            nonce: Some(casino_token_record_nonce),
        };
        let (player_address_string, player_address) = test_helpers::address(1);
        let random_roulette_spin_result = 1_u8;
        let player_bet_number = random_roulette_spin_result; // Player wins.
        let player_bet_amount_of_tokens = 1_u64;
        let player_amount_of_available_tokens = 100_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::Record(casino_token_record),
            jaleo::UserInputValueType::Address(player_address),
            jaleo::UserInputValueType::U8(random_roulette_spin_result),
            jaleo::UserInputValueType::U8(player_bet_number),
            jaleo::UserInputValueType::U64(player_bet_amount_of_tokens),
            jaleo::UserInputValueType::U64(player_amount_of_available_tokens),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec![
            "r0",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "35u64",
            "r7",
            "r0.amount",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r0.owner",
            "r0.gates",
            "0u64",
            "r14",
            "r15",
        ];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Casino token record.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r0 {
            assert_eq!(record.owner.value().unwrap(), casino_address_string);
            assert_eq!(record.gates.value().unwrap(), casino_token_record_gates);
            assert_eq!(
                record.entries.get("amount").unwrap().value().unwrap(),
                casino_token_record_amount.to_string()
            );
            // assert_eq!(record.nonce, casino_token_record_nonce);
        } else {
            panic!("r0 should be a record");
        }

        // Player address.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), player_address_string);

        // Random roulette spin result.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r2.value().unwrap(), random_roulette_spin_result.to_string());

        // Player bet number.
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleUInt8(_)));
        assert_eq!(r3.value().unwrap(), player_bet_number.to_string());

        // Player bet amount of tokens.
        let r4 = function_variables["r4"].as_ref().unwrap();
        assert!(matches!(r4, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r4.value().unwrap(), player_bet_amount_of_tokens.to_string());

        // Player amount of available tokens.
        let r5 = function_variables["r5"].as_ref().unwrap();
        assert!(matches!(r5, vmtropy::CircuitIOType::SimpleUInt64(_)));

        // Player wins
        let r6 = function_variables["r6"].as_ref().unwrap();
        assert!(matches!(r6, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r6.value().unwrap(), "true");

        // Reward
        let r7 = function_variables["r7"].as_ref().unwrap();
        assert!(matches!(r7, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r7.value().unwrap(), reward.to_string());

        // Casino amount of tokens if it wins
        let r8 = function_variables["r8"].as_ref().unwrap();
        assert!(matches!(r8, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r8.value().unwrap(),
            (casino_token_record_amount + player_bet_amount_of_tokens).to_string()
        );

        // Casino amount of tokens if it loses
        let r9 = function_variables["r9"].as_ref().unwrap();
        assert!(matches!(r9, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r9.value().unwrap(),
            (casino_token_record_amount - reward).to_string()
        );

        // Player amount of tokens if it wins
        let r10 = function_variables["r10"].as_ref().unwrap();
        assert!(matches!(r10, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r10.value().unwrap(),
            (player_amount_of_available_tokens + 35).to_string()
        );

        // Player amount of tokens if it loses
        let r11 = function_variables["r11"].as_ref().unwrap();
        assert!(matches!(r11, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(
            r11.value().unwrap(),
            (player_amount_of_available_tokens - player_bet_amount_of_tokens).to_string()
        );

        // Casino money after game
        let r12 = function_variables["r12"].as_ref().unwrap();
        assert!(matches!(r12, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r12.value().unwrap(), r9.value().unwrap());

        // Player money after game
        let r13 = function_variables["r13"].as_ref().unwrap();
        assert!(matches!(r13, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r13.value().unwrap(), r10.value().unwrap());

        // Casino token record after the bet
        let r14 = function_variables["r14"].as_ref().unwrap();
        assert!(matches!(r14, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r14 {
            assert_eq!(record.owner.value().unwrap(), casino_address_string);
            assert_eq!(record.gates.value().unwrap(), casino_token_record_gates);
            assert_eq!(
                record.entries.get("amount").unwrap().value().unwrap(),
                r12.value().unwrap()
            );
        } else {
            panic!("r14 should be a record");
        }

        // Player token record after the bet
        let r15 = function_variables["r15"].as_ref().unwrap();
        assert!(matches!(r15, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r15 {
            assert_eq!(record.owner.value().unwrap(), player_address_string);
            assert_eq!(record.gates.value().unwrap(), 0_u64);
            assert_eq!(
                record.entries.get("amount").unwrap().value().unwrap(),
                r13.value().unwrap()
            );
        } else {
            panic!("r15 should be a record");
        }

        assert_that_proof_for_function_execution_is_correct(program, &[], &proof, MAKE_BET);
    }

    #[test]
    fn test_psd_bits_mod() {
        let (program, function) = get_aleo_roulette_function(PSD_BITS_MOD);

        let user_inputs = vec![
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::Boolean(false),
            jaleo::UserInputValueType::U16(0_u16),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec![
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "1u16", "0u16", "r7", "2u16", "r8", "4u16",
            "r9", "8u16", "r10", "16u16", "r11", "32u16", "r12", "r13", "r14", "r15", "r16", "r17",
            "r18", "r19", "r20", "r21", "r22", "r23", "37u16", "r24", "r25", "r26", "r27",
        ];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // r0
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r0.value().unwrap(), "false");

        // r1
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r1.value().unwrap(), "false");

        // r2
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r2.value().unwrap(), "false");

        // r3
        let r3 = function_variables["r3"].as_ref().unwrap();
        assert!(matches!(r3, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r3.value().unwrap(), "false");

        // r4
        let r4 = function_variables["r4"].as_ref().unwrap();
        assert!(matches!(r4, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r4.value().unwrap(), "false");

        // r5
        let r5 = function_variables["r5"].as_ref().unwrap();
        assert!(matches!(r5, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r5.value().unwrap(), "false");

        // r6
        let r6 = function_variables["r6"].as_ref().unwrap();
        assert!(matches!(r6, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r6.value().unwrap(), "0");

        // r7
        let r7 = function_variables["r7"].as_ref().unwrap();
        assert!(matches!(r7, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r7.value().unwrap(), "1");

        // r8
        let r8 = function_variables["r8"].as_ref().unwrap();
        assert!(matches!(r8, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r8.value().unwrap(), "2");

        // r9
        let r9 = function_variables["r9"].as_ref().unwrap();
        assert!(matches!(r9, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r9.value().unwrap(), "4");

        // r10
        let r10 = function_variables["r10"].as_ref().unwrap();
        assert!(matches!(r10, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r10.value().unwrap(), "8");

        // r11
        let r11 = function_variables["r11"].as_ref().unwrap();
        assert!(matches!(r11, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r11.value().unwrap(), "16");

        // r12
        let r12 = function_variables["r12"].as_ref().unwrap();
        assert!(matches!(r12, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r12.value().unwrap(), "32");

        // r13
        let r13 = function_variables["r13"].as_ref().unwrap();
        assert!(matches!(r13, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r13.value().unwrap(), "0");

        // r14
        let r14 = function_variables["r14"].as_ref().unwrap();
        assert!(matches!(r14, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r14.value().unwrap(), "0");

        // r15
        let r15 = function_variables["r15"].as_ref().unwrap();
        assert!(matches!(r15, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r15.value().unwrap(), "0");

        // r16
        let r16 = function_variables["r16"].as_ref().unwrap();
        assert!(matches!(r16, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r16.value().unwrap(), "0");

        // r17
        let r17 = function_variables["r17"].as_ref().unwrap();
        assert!(matches!(r17, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r17.value().unwrap(), "0");

        // r18
        let r18 = function_variables["r18"].as_ref().unwrap();
        assert!(matches!(r18, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r18.value().unwrap(), "0");

        // r19
        let r19 = function_variables["r19"].as_ref().unwrap();
        assert!(matches!(r19, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r19.value().unwrap(), "0");

        // r20
        let r20 = function_variables["r20"].as_ref().unwrap();
        assert!(matches!(r20, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r20.value().unwrap(), "0");

        // r21
        let r21 = function_variables["r21"].as_ref().unwrap();
        assert!(matches!(r21, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r21.value().unwrap(), "0");

        // r22
        let r22 = function_variables["r22"].as_ref().unwrap();
        assert!(matches!(r22, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r22.value().unwrap(), "0");

        // r23
        let r23 = function_variables["r23"].as_ref().unwrap();
        assert!(matches!(r23, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r23.value().unwrap(), "0");

        // r24
        let r24 = function_variables["r24"].as_ref().unwrap();
        assert!(matches!(r24, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r24.value().unwrap(), "0");

        // r25
        let r25 = function_variables["r25"].as_ref().unwrap();
        assert!(matches!(r25, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r25.value().unwrap(), "0");

        // r26
        let r26 = function_variables["r26"].as_ref().unwrap();
        assert!(matches!(r26, vmtropy::CircuitIOType::SimpleUInt16(_)));
        assert_eq!(r26.value().unwrap(), "0");

        // r27
        let r27 = function_variables["r27"].as_ref().unwrap();
        assert!(matches!(r27, vmtropy::CircuitIOType::SimpleBoolean(_)));
        assert_eq!(r27.value().unwrap(), "true");

        assert_that_proof_for_function_execution_is_correct(
            program,
            &user_inputs,
            &proof,
            PSD_BITS_MOD,
        );
    }

    #[test]
    fn test_records() {
        let (program, function) = get_aleo_records_function("mint");

        let (address_string, address_bytes) = test_helpers::address(0);
        let amount_to_mint = 1_u64;

        let user_inputs = vec![
            UserInputValueType::U64(amount_to_mint),
            UserInputValueType::Address(address_bytes),
        ];

        let (function_variables, proof) =
            vmtropy::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "0u64", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Address.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, vmtropy::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), amount_to_mint.to_string());

        // Amount to mint.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, vmtropy::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), address_string);

        // Constant literal (record gates).
        let constant_0u64 = function_variables["0u64"].as_ref().unwrap();
        assert!(matches!(
            constant_0u64,
            vmtropy::CircuitIOType::SimpleUInt64(_)
        ));
        assert_eq!(constant_0u64.value().unwrap(), "0".to_owned());

        // Minted output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, vmtropy::CircuitIOType::SimpleRecord(_)));
        if let vmtropy::CircuitIOType::SimpleRecord(record) = r2 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 0);
            // assert_ne!(record.nonce, ConstraintF::default());
        } else {
            panic!("r2 should be a record");
        }

        assert_that_proof_for_function_execution_is_correct(
            program,
            &[
                jaleo::UserInputValueType::U64(amount_to_mint),
                jaleo::UserInputValueType::Address(address_bytes),
            ],
            &proof,
            "mint",
        );
    }
}
