cfg_if::cfg_if! {
    if #[cfg(any(feature = "vmtropy_backend", feature = "snarkvm_backend", feature = "vmtropy_backend_flamegraph", feature = "snarkvm_backend_flamegraph"))] {
        use super::{helpers::test_helpers, vm::{self, Program, Identifier, PrivateKey}};
        use ark_ff::UniformRand;
        use ark_relations::r1cs::ConstraintSystem;
        use ark_std::rand::thread_rng;
        use criterion::{Criterion, BenchmarkId};
        use simpleworks::gadgets::ConstraintF;
        use snarkvm::prelude::Parser;
        use vmtropy::jaleo;

        const ALEO_ROULETTE_PROGRAM: &str = "programs/roulette.aleo";
        const PSD_HASH: &str = "psd_hash";
        const MAKE_BET: &str = "make_bet";
        const MINT_CASINO_TOKEN_RECORD: &str = "mint_casino_token_record";
        const PSD_BITS_MOD: &str = "psd_bits_mod";

        fn get_aleo_roulette_program() -> Program {
            let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push(ALEO_ROULETTE_PROGRAM);
            let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
            let (_, program) = Program::parse(&program_string).unwrap();

            program
        }

        pub fn benchmark_psd_hash_execution(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_roulette");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();
            
            let private_key = PrivateKey::new(rng).unwrap();
            
            let program = get_aleo_roulette_program();
            let function_name = Identifier::try_from(PSD_HASH).unwrap();
            
            let inputs = [jaleo::UserInputValueType::U32(0_u32)];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("psd_hash"), |b| {
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

        pub fn benchmark_mint_casino_token_record_execution(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_roulette");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            
   
   let program = get_aleo_roulette_program();         let function_name = Identifier::try_from(MINT_CASINO_TOKEN_RECORD).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();
   

            let (_address_string, address_bytes) = test_helpers::address(0);
            let amount_to_mint = 1_u64;
            let inputs = vec![
                jaleo::UserInputValueType::Address(address_bytes),
                jaleo::UserInputValueType::U64(amount_to_mint),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("mint_casino_token_record"), |b| {
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

        pub fn benchmark_make_bet_execution(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_roulette");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();
            
            let private_key = PrivateKey::new(rng).unwrap();
            
            let program = get_aleo_roulette_program();
            let function_name = Identifier::try_from(MAKE_BET).unwrap();

            let (_casino_address_string, casino_address) = test_helpers::address(0);
            let casino_token_record_gates = 0_u64;
            let casino_token_record_amount = 100_u64;
            let mut casino_token_record_data = jaleo::RecordEntriesMap::new();
            casino_token_record_data.insert(
                "amount".to_owned(),
                vmtropy::jaleo::UserInputValueType::U64(casino_token_record_amount),
            );
            let casino_token_record_nonce = ConstraintF::rand(&mut thread_rng());

            let casino_token_record = jaleo::Record {
                owner: casino_address,
                gates: casino_token_record_gates,
                data: casino_token_record_data,
                nonce: casino_token_record_nonce,
            };
            let (_player_address_string, player_address) = test_helpers::address(1);
            let random_roulette_spin_result = 1_u8;
            let player_bet_number = random_roulette_spin_result; // Player wins.
            let player_bet_amount_of_tokens = 1_u64;
            let player_amount_of_available_tokens = 100_u64;

            let inputs = vec![
                jaleo::UserInputValueType::Record(casino_token_record),
                jaleo::UserInputValueType::Address(player_address),
                jaleo::UserInputValueType::U8(random_roulette_spin_result),
                jaleo::UserInputValueType::U8(player_bet_number),
                jaleo::UserInputValueType::U64(player_bet_amount_of_tokens),
                jaleo::UserInputValueType::U64(player_amount_of_available_tokens),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("make_bet"), |b| {
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

        pub fn benchmark_psd_bits_mod_execution(c: &mut Criterion) {
            let mut group = c.benchmark_group("aleo_roulette");

            let rng = &mut simpleworks::marlin::generate_rand();
            let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng).unwrap();

            let private_key = PrivateKey::new(rng).unwrap();
            
            let program = get_aleo_roulette_program();
            let function_name = Identifier::try_from(PSD_BITS_MOD).unwrap();

            let inputs = vec![
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::Boolean(false),
                jaleo::UserInputValueType::U16(0_u16),
            ];

            group.sample_size(10);
            group.bench_function(BenchmarkId::from_parameter("psd_bits_mod"), |b| {
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
