use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use parking_lot::{lock_api::RwLock, RawRwLock};
use rand::rngs::{StdRng, ThreadRng};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use simpleworks::marlin::{ConstraintSystemRef, UniversalSRS};
use snarkvm::prelude::{Boolean, Value};
use snarkvm::{
    circuit::AleoV0,
    console::types::string::Integer,
    prelude::{Balance, CallStack, Literal, Network, Owner, Plaintext, Testnet3, ToBits, Uniform},
};
use std::{ops::Deref, str::FromStr, sync::Arc};

mod stack;

pub type Function = snarkvm::prelude::Function<Testnet3>;
pub type Address = snarkvm::prelude::Address<Testnet3>;
pub type Identifier = snarkvm::prelude::Identifier<Testnet3>;
pub type Program = snarkvm::prelude::Program<Testnet3>;
pub type Ciphertext = snarkvm::prelude::Ciphertext<Testnet3>;
pub type Record = snarkvm::prelude::Record<Testnet3, snarkvm::prelude::Plaintext<Testnet3>>;
type Execution = snarkvm::prelude::Execution<Testnet3>;
pub type EncryptedRecord = snarkvm::prelude::Record<Testnet3, Ciphertext>;
pub type ViewKey = snarkvm::prelude::ViewKey<Testnet3>;
pub type PrivateKey = snarkvm::prelude::PrivateKey<Testnet3>;
pub type Field = snarkvm::prelude::Field<Testnet3>;
pub type Origin = snarkvm::prelude::Origin<Testnet3>;
pub type Output = snarkvm::prelude::Output<Testnet3>;
pub type ProgramID = snarkvm::prelude::ProgramID<Testnet3>;
pub type VerifyingKey = snarkvm::prelude::VerifyingKey<Testnet3>;
pub type ProvingKey = snarkvm::prelude::ProvingKey<Testnet3>;
pub type Deployment = snarkvm::prelude::Deployment<Testnet3>;
pub type Transition = snarkvm::prelude::Transition<Testnet3>;

/// This struct is nothing more than a wrapper around the actual IndexMap that is used
/// for the verifying keys map. Why does it exist? The problem comes from the vmtropy backend.
/// Arkworks' verifying keys do not implement the regular `Serialize`/`Deserialize` traits,
/// as they use their own custom `CanonicalSerialize`/`CanonicalDeserialize` ones. To implement
/// the regular `Serialize`/`Deserialize` traits, we wrapped the IndexMap around this struct.
/// To preserve APIs across the two backends, we did the same here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKeyMap {
    pub map: IndexMap<Identifier, VerifyingKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramBuild {
    pub map: IndexMap<Identifier, (ProvingKey, VerifyingKey)>,
}

/// Generate proving and verifying keys for the given function.
pub fn synthesize_function_keys(
    program: &Program,
    rng: &mut ThreadRng,
    function_name: &Identifier,
) -> Result<(ProvingKey, VerifyingKey)> {
    let stack = stack::new_init(program)?;
    stack.synthesize_key::<AleoV0, _>(function_name, rng)?;
    let proving_key = stack.proving_keys.read().get(function_name).cloned();
    let proving_key = proving_key.ok_or_else(|| anyhow!("proving key not found for identifier"))?;

    let verifying_key = stack.verifying_keys.read().get(function_name).cloned();
    let verifying_key =
        verifying_key.ok_or_else(|| anyhow!("verifying key not found for identifier"))?;

    Ok((proving_key, verifying_key))
}

// Generates a program deployment for source transactions
pub fn generate_program(program_string: &str) -> Result<Program> {
    // Verify program is valid by parsing it and returning it
    Program::from_str(program_string)
}

fn user_input_value_to_aleo_value(
    values: &[vmtropy::jaleo::UserInputValueType],
) -> Vec<Value<Testnet3>> {
    values
        .iter()
        .map(|value| match value {
            vmtropy::jaleo::UserInputValueType::Address(address) => {
                let address = std::str::from_utf8(address).unwrap();
                let address = Address::from_str(address).unwrap();
                Value::Plaintext(Plaintext::from(Literal::Address(address)))
            }
            vmtropy::jaleo::UserInputValueType::Boolean(boolean) => {
                Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(*boolean))))
            }
            vmtropy::jaleo::UserInputValueType::U8(value) => {
                Value::Plaintext(Plaintext::from(Literal::U8(Integer::new(*value))))
            }
            vmtropy::jaleo::UserInputValueType::U16(value) => {
                Value::Plaintext(Plaintext::from(Literal::U16(Integer::new(*value))))
            }
            vmtropy::jaleo::UserInputValueType::U32(value) => {
                Value::Plaintext(Plaintext::from(Literal::U32(Integer::new(*value))))
            }
            vmtropy::jaleo::UserInputValueType::U64(value) => {
                Value::Plaintext(Plaintext::from(Literal::U64(Integer::new(*value))))
            }
            vmtropy::jaleo::UserInputValueType::Record(_record) => {
                todo!()
            }
            _ => unreachable!("At least for the actual benchmarks"),
        })
        .collect()
}

pub fn execute_function(
    program: &Program,
    function_name: &Identifier,
    inputs: &[vmtropy::jaleo::UserInputValueType],
    private_key: &PrivateKey,
    _universal_srs: &UniversalSRS,
    _constraint_system: ConstraintSystemRef,
    _rng: &mut StdRng,
) -> Result<Arc<parking_lot::lock_api::RwLock<parking_lot::RawRwLock, Execution>>> {
    let rng = &mut rand::thread_rng();

    let stack = stack::new_init(program)?;
    let (proving_key, _verifying_key) = synthesize_function_keys(program, rng, function_name)?;

    stack.insert_proving_key(function_name, proving_key)?;

    let authorization = stack.authorize::<AleoV0, _>(
        private_key,
        *function_name,
        &user_input_value_to_aleo_value(inputs),
        rng,
    )?;
    let execution: Arc<RwLock<RawRwLock, _>> = Arc::new(RwLock::new(Execution::new()));

    // Execute the circuit.
    let _ = stack.execute_function::<AleoV0, _>(
        CallStack::execute(authorization, execution.clone())?,
        rng,
    )?;

    Ok(execution)
}

/// Extract the record gates (the minimal credits unit) as a u64 integer, instead of a snarkvm internal type.
pub fn gates(record: &Record) -> u64 {
    *record.gates().deref().deref()
}

/// A helper method to derive the serial number from the private key and commitment.
pub fn compute_serial_number(private_key: PrivateKey, commitment: Field) -> Result<Field> {
    // Compute the generator `H` as `HashToGroup(commitment)`.
    let h = Testnet3::hash_to_group_psd2(&[Testnet3::serial_number_domain(), commitment])?;
    // Compute `gamma` as `sk_sig * H`.
    let gamma = h * private_key.sk_sig();
    // Compute `sn_nonce` as `Hash(COFACTOR * gamma)`.
    let sn_nonce = Testnet3::hash_to_scalar_psd2(&[
        Testnet3::serial_number_domain(),
        gamma.mul_by_cofactor().to_x_coordinate(),
    ])?;
    // Compute `serial_number` as `Commit(commitment, sn_nonce)`.
    Testnet3::commit_bhp512(
        &(Testnet3::serial_number_domain(), commitment).to_bits_le(),
        &sn_nonce,
    )
}

/// Generate a record for a specific program with the given attributes,
/// by using the given seed to deterministically generate a nonce.
/// This could be replaced by a more user-friendly record constructor.
pub fn mint_record(
    program_id: &str,
    record_name: &str,
    owner_view_key: &ViewKey,
    gates: u64,
    seed: u64,
) -> Result<(Field, EncryptedRecord)> {
    // TODO have someone verify/audit this, probably it's unsafe or breaks cryptographic assumptions

    let owner_address = Address::try_from(owner_view_key)?;
    let owner = Owner::Private(Plaintext::Literal(
        Literal::Address(owner_address),
        Default::default(),
    ));
    let amount = Integer::new(gates);
    let gates = Balance::Private(Plaintext::Literal(Literal::U64(amount), Default::default()));
    let empty_data = IndexMap::new();

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let randomizer = Uniform::rand(&mut rng);
    let nonce = Testnet3::g_scalar_multiply(&randomizer);

    let public_record = Record::from_plaintext(owner, gates, empty_data, nonce)?;
    let record_name = Identifier::from_str(record_name)?;
    let program_id = ProgramID::from_str(program_id)?;
    let commitment = public_record.to_commitment(&program_id, &record_name)?;
    let encrypted_record = public_record.encrypt(randomizer)?;
    Ok((commitment, encrypted_record))
}
