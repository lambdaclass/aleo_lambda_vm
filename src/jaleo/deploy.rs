use crate::{build_program, helpers};
use anyhow::{bail, ensure, Result};
use ark_std::rand::rngs::StdRng;
use indexmap::IndexMap;
use serde::{
    de,
    ser::{self, Error, SerializeMap},
    Deserialize, Serialize,
};
use simpleworks::{
    marlin::serialization::{deserialize_verifying_key, serialize_verifying_key},
    marlin::VerifyingKey,
};
use snarkvm::prelude::{Itertools, Program, Testnet3};
use std::fmt::Debug;

pub type VerifyingKeyMap = IndexMap<String, VerifyingKey>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub program: Program<Testnet3>,
    #[serde(
        serialize_with = "serialize_verifying_key_map",
        deserialize_with = "deserialize_verifying_key_map"
    )]
    pub verifying_keys: VerifyingKeyMap,
}

pub fn serialize_verifying_key_map<S>(
    verifying_key_map: &VerifyingKeyMap,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut s = serializer.serialize_map(Some(verifying_key_map.len()))?;
    for (k, v) in verifying_key_map {
        let serialized_verifying_key =
            hex::encode(serialize_verifying_key(v.clone()).map_err(ser::Error::custom)?);
        s.serialize_entry(&k, &serialized_verifying_key)?;
    }
    s.end()
}

pub fn deserialize_verifying_key_map<'de, D>(deserializer: D) -> Result<VerifyingKeyMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    type IntermediateVerifyingKeyMap = IndexMap<String, String>;

    let intermediate_verifying_key_map = IntermediateVerifyingKeyMap::deserialize(deserializer)?;
    let mut verifying_key_map = VerifyingKeyMap::new();
    for (k, v) in intermediate_verifying_key_map {
        let bytes_verifying_key = hex::decode(v).map_err(de::Error::custom)?;
        let verifying_key =
            deserialize_verifying_key(bytes_verifying_key).map_err(de::Error::custom)?;
        verifying_key_map.insert(k, verifying_key);
    }
    Ok(verifying_key_map)
}

impl Debug for Deployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut verifying_keys = IndexMap::new();
        for (k, v) in self.verifying_keys.iter() {
            let serialized_verifying_key =
                hex::encode(serialize_verifying_key(v.clone()).map_err(std::fmt::Error::custom)?);
            verifying_keys.insert(k.clone(), serialized_verifying_key.clone());
        }
        f.debug_struct("Deployment")
            .field("program", &self.program)
            .field("verifying_keys", &verifying_keys)
            .finish()
    }
}

// these struct-level functions should probably not be in the Vm level
pub fn generate_deployment(program_string: &str) -> Result<Deployment> {
    // NOTE: we're skipping the part of imported programs
    // https://github.com/Entropy1729/snarkVM/blob/2c4e282df46ed71c809fd4b49738fd78562354ac/vm/package/deploy.rs#L149

    let (program, program_build) = build_program(program_string)?;
    let verifying_keys: VerifyingKeyMap = program_build
        .into_iter()
        .map(|(function_name, (_proving_key, verifying_key))| (function_name, verifying_key))
        .collect();

    Ok(Deployment {
        program,
        verifying_keys,
    })
}

/// Checks each function in the program on the given verifying key and certificate.
pub fn verify_deployment(deployment: &Deployment, rng: &mut StdRng) -> Result<()> {
    // Retrieve the program.
    let program = &deployment.program;
    // Retrieve the program ID.
    let program_id = program.id();
    // Retrieve the verifying keys.
    let verifying_keys = &deployment.verifying_keys;

    // Sanity Checks //

    // Ensure the program matches.
    ensure!(
        program == &deployment.program,
        "The stack program does not match the deployment program"
    );
    // Ensure the program network-level domain (NLD) is correct.
    ensure!(
        program_id.is_aleo(),
        "Program '{program_id}' has an incorrect network-level domain (NLD)"
    );
    // Ensure the program contains functions.
    ensure!(
        !program.functions().is_empty(),
        "No functions present in the deployment for program '{program_id}'"
    );
    // Ensure the deployment contains verifying keys.
    ensure!(
        !verifying_keys.is_empty(),
        "No verifying keys present in the deployment for program '{program_id}'"
    );

    // Check Verifying Keys //

    // Ensure the number of verifying keys matches the number of program functions.
    if verifying_keys.len() != program.functions().len() {
        bail!("The number of verifying keys does not match the number of program functions");
    }

    // Ensure the program functions are in the same order as the verifying keys.
    for ((function_name, function), candidate_name) in
        program.functions().iter().zip_eq(verifying_keys.keys())
    {
        // Ensure the function name is correct.
        if function_name != function.name() {
            bail!(
                "The function key is '{function_name}', but the function name is '{}'",
                function.name()
            )
        }
        // Ensure the function name with the verifying key is correct.
        if candidate_name != &function.name().to_string() {
            bail!(
                "The verifier key is '{candidate_name}', but the function name is '{}'",
                function.name()
            )
        }
    }

    // Iterate through the program functions.
    for function in program.functions().values() {
        // Sample the inputs.
        let inputs = helpers::default_user_inputs(function)?;
        let _result = crate::execute_function(function, &inputs, rng)?;
    }
    Ok(())
}
