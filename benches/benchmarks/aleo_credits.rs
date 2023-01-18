cfg_if::cfg_if! {
    if #[cfg(any(feature = "vmtropy_backend", feature = "snarkvm_backend", feature = "vmtropy_backend_flamegraph", feature = "snarkvm_backend_flamegraph"))] {
        use super::{helpers::test_helpers, vm::{Program, Function, Identifier}};
        use ark_relations::r1cs::ConstraintSystem;
        use criterion::{Criterion, BenchmarkId};
        use simpleworks::gadgets::ConstraintF;
        use snarkvm::prelude::Parser;
        use vmtropy::jaleo;

        const ALEO_CREDITS_PROGRAM: &str = "programs/credits.aleo";
        const GENESIS: &str = "genesis";
        const MINT: &str = "mint";
        const TRANSFER: &str = "transfer";
        const COMBINE: &str = "combine";
        const SPLIT: &str = "split";
        const FEE: &str = "fee";

        fn get_aleo_credits_function(function_name: &str) -> (Program, Function) {
            let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push(ALEO_CREDITS_PROGRAM);
            let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
            let (_, program) = Program::parse(&program_string).unwrap();
            let function = program
                .get_function(&Identifier::try_from(function_name).unwrap())
                .unwrap();

            (program, function)
        }

        pub fn execute_genesis(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(GENESIS);

            let (_address_string, address_bytes) = test_helpers::address(0);
            let genesis_credits = 1_u64;

            let user_inputs = vec![
                jaleo::UserInputValueType::Address(address_bytes),
                jaleo::UserInputValueType::U64(genesis_credits),
            ];

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("genesis"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_mint(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(MINT);

            let (_address_string, address_bytes) = test_helpers::address(0);
            let credits_to_mint = 1_u64;

            let user_inputs = vec![
                jaleo::UserInputValueType::Address(address_bytes),
                jaleo::UserInputValueType::U64(credits_to_mint),
            ];

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("mint"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_transfer(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(TRANSFER);

            let (_sender_address_string, sender_address_bytes) = test_helpers::address(0);
            let initial_balance = 1_u64;
            let amount_to_transfer = initial_balance;
            let (_receiver_address_string, receiver_address_bytes) = test_helpers::address(0);

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

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("transfer"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_combine(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(COMBINE);

            let (_address_string, address_bytes) = test_helpers::address(0);
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

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("combine"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_split(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(SPLIT);

            let (_address_string, address_bytes) = test_helpers::address(0);
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

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("split"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }

        pub fn execute_fee(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_credits");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let (program, function) = get_aleo_credits_function(FEE);

            let (_address_string, address_bytes) = test_helpers::address(0);
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

            group.sample_size(100);
            group.bench_function(BenchmarkId::from_parameter("fee"), |b| {
                b.iter(|| {
                    vmtropy::_execute_function(&program, &function, &user_inputs, universal_srs.as_ref(), ConstraintSystem::<ConstraintF>::new_ref(), rng).unwrap()
                })
            });
            group.finish();
        }
    }
}
