cfg_if::cfg_if! {
    if #[cfg(any(feature = "lambdavm_backend", feature = "snarkvm_backend", feature = "lambdavm_backend_flamegraph", feature = "snarkvm_backend_flamegraph"))] {
        use super::{helpers::test_helpers, vm::{self, Program, Identifier, PrivateKey}};
        use ark_relations::r1cs::ConstraintSystem;
        use criterion::{Criterion, BenchmarkId};
        use simpleworks::gadgets::ConstraintF;
        use snarkvm::prelude::Parser;
        use lambdavm::jaleo;
        use lambdavm::helpers::random_nonce;

        const ALEO_CREDITS_PROGRAM: &str = "programs/credits.aleo";
        const GENESIS: &str = "genesis";
        const MINT: &str = "mint";
        const TRANSFER: &str = "transfer";
        const COMBINE: &str = "combine";
        const SPLIT: &str = "split";
        const FEE: &str = "fee";

        fn get_aleo_credits_program() -> Program {
            let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push(ALEO_CREDITS_PROGRAM);
            let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
            let (_, program) = Program::parse(&program_string).unwrap();

            program
        }

        pub fn execute_genesis(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(GENESIS).unwrap();

            let (_address_string, address_bytes) = test_helpers::address();
            let genesis_credits = 1_u64;

            let inputs = vec![
                jaleo::UserInputValueType::Address(address_bytes),
                jaleo::UserInputValueType::U64(genesis_credits),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("genesis"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_mint(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(MINT).unwrap();

            let (_address_string, address_bytes) = test_helpers::address();
            let credits_to_mint = 1_u64;

            let inputs = vec![
                jaleo::UserInputValueType::Address(address_bytes),
                jaleo::UserInputValueType::U64(credits_to_mint),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("mint"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_transfer(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(TRANSFER).unwrap();

            let (_sender_address_string, sender_address_bytes) = test_helpers::address();
            let initial_balance = 1_u64;
            let amount_to_transfer = initial_balance;
            let (_receiver_address_string, receiver_address_bytes) = test_helpers::address();

            let inputs = vec![
                test_helpers::input_record(
                    sender_address_bytes,
                    initial_balance,
                    jaleo::RecordEntriesMap::default(),
                    random_nonce(),
                ),
                jaleo::UserInputValueType::Address(receiver_address_bytes),
                jaleo::UserInputValueType::U64(amount_to_transfer),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("transfer"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_combine(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(COMBINE).unwrap();

            let (_address_string, address_bytes) = test_helpers::address();
            let initial_balance = 1_u64;

            let first_record_nonce = test_helpers::sample_nonce();
            let second_record_nonce = test_helpers::sample_nonce();

            let inputs = vec![
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

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("combine"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_split(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(SPLIT).unwrap();

            let (_address_string, address_bytes) = test_helpers::address();
            let gates_of_existing_record = 2_u64;
            let gates_for_new_record = 1_u64;
            let nonce = test_helpers::sample_nonce();

            let inputs = vec![
                test_helpers::input_record(
                    address_bytes,
                    gates_of_existing_record,
                    jaleo::RecordEntriesMap::default(),
                    nonce,
                ),
                jaleo::UserInputValueType::U64(gates_for_new_record),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("split"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_fee(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();

            let program = get_aleo_credits_program();
            let function_name = Identifier::try_from(FEE).unwrap();

            let (_address_string, address_bytes) = test_helpers::address();
            let initial_balance = 1_u64;
            let fee = 1_u64;
            let nonce = test_helpers::sample_nonce();

            let inputs = vec![
                test_helpers::input_record(
                    address_bytes,
                    initial_balance,
                    jaleo::RecordEntriesMap::default(),
                    nonce,
                ),
                jaleo::UserInputValueType::U64(fee),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("fee"), |b| {
                b.iter(|| {
                    vm::execute_function(
                        &program,
                        &function_name,
                        &inputs,
                        &private_key,
                        universal_srs.as_ref(),
                        ConstraintSystem::<ConstraintF>::new_ref(),
                        rng
                    ).unwrap()
                })
            });
            group.finish();
        }
    }
}
