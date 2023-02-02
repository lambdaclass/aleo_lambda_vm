#[cfg(test)]
mod cast_tests {
    use crate::helpers::test_helpers;
    use snarkvm::prelude::Parser;
    use lambdavm::jaleo::{
        Identifier, Program,
        UserInputValueType::{U16, U32, U64},
    };

    #[test]
    fn test_cast_custom_record() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/token.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
        let function = program
            .get_function(&Identifier::try_from("mint").unwrap())
            .unwrap();

        let (address_string, address_bytes) = test_helpers::address();
        let amount_to_mint = 1_u64;

        let user_inputs = vec![
            jaleo::UserInputValueType::U64(amount_to_mint),
            jaleo::UserInputValueType::Address(address_bytes),
        ];

        let (function_variables, _proof) =
            lambdavm::execute_function(&program, &function, &user_inputs).unwrap();

        let expected_function_variables = vec!["r0", "r1", "0u64", "r2"];
        for (register, expected_register) in
            function_variables.keys().zip(expected_function_variables)
        {
            assert_eq!(register, expected_register);
        }

        // Amount to mint.
        let r0 = function_variables["r0"].as_ref().unwrap();
        assert!(matches!(r0, lambdavm::CircuitIOType::SimpleUInt64(_)));
        assert_eq!(r0.value().unwrap(), amount_to_mint.to_string());

        // Address.
        let r1 = function_variables["r1"].as_ref().unwrap();
        assert!(matches!(r1, lambdavm::CircuitIOType::SimpleAddress(_)));
        assert_eq!(r1.value().unwrap(), address_string);

        // Constant literal (record gates).
        let constant_0u64 = function_variables["0u64"].as_ref().unwrap();
        assert!(matches!(
            constant_0u64,
            lambdavm::CircuitIOType::SimpleUInt64(_)
        ));
        assert_eq!(constant_0u64.value().unwrap(), "0".to_owned());

        // Minted output record.
        let r2 = function_variables["r2"].as_ref().unwrap();
        assert!(matches!(r2, lambdavm::CircuitIOType::SimpleRecord(_)));
        if let lambdavm::CircuitIOType::SimpleRecord(record) = r2 {
            assert_eq!(record.owner.value().unwrap(), address_string);
            assert_eq!(record.gates.value().unwrap(), 0);
            assert_ne!(record.nonce, ConstraintF::default());
        } else {
            panic!("r2 should be a record");
        }

        let (_program, program_build) = lambdavm::build_program(&program_string).unwrap();
        let (_function_proving_key, function_verifying_key) = program_build
            .map
            .get(&Identifier::try_from("mint").unwrap())
            .unwrap();
        let public_inputs = [];
        assert!(
            lambdavm::verify_proof(function_verifying_key.clone(), &public_inputs, &_proof).unwrap()
        )
    }
}
