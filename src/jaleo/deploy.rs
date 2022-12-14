use super::Program;
use crate::build_program;
use anyhow::{bail, ensure, Result};
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
use snarkvm::prelude::Itertools;
use std::fmt::Debug;

#[derive(Clone)]
pub struct VerifyingKeyMap {
    pub map: IndexMap<String, VerifyingKey>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Deployment {
    pub program: Program,
    pub verifying_keys: VerifyingKeyMap,
}

impl Serialize for VerifyingKeyMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_map(Some(self.map.len()))?;
        for (k, v) in &self.map {
            let serialized_verifying_key =
                hex::encode(serialize_verifying_key(v.clone()).map_err(ser::Error::custom)?);
            s.serialize_entry(&k, &serialized_verifying_key)?;
        }
        s.end()
    }
}

impl<'de> Deserialize<'de> for VerifyingKeyMap {
    fn deserialize<D>(deserializer: D) -> Result<VerifyingKeyMap, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // It's called EncodedVerifyingKeyMap because its values are encoded.
        type EncodedVerifyingKeyMap = IndexMap<String, String>;

        let intermediate_verifying_key_map = EncodedVerifyingKeyMap::deserialize(deserializer)?;
        let mut verifying_key_map = IndexMap::new();
        for (k, v) in intermediate_verifying_key_map {
            let bytes_verifying_key = hex::decode(v).map_err(de::Error::custom)?;
            let verifying_key =
                deserialize_verifying_key(bytes_verifying_key).map_err(de::Error::custom)?;
            verifying_key_map.insert(k, verifying_key);
        }
        Ok(VerifyingKeyMap {
            map: verifying_key_map,
        })
    }
}

impl Debug for VerifyingKeyMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut verifying_keys = IndexMap::new();
        for (k, v) in self.map.iter() {
            let serialized_verifying_key =
                hex::encode(serialize_verifying_key(v.clone()).map_err(std::fmt::Error::custom)?);
            verifying_keys.insert(k.clone(), serialized_verifying_key.clone());
        }
        IndexMap::fmt(&verifying_keys, f)
    }
}

// these struct-level functions should probably not be in the Vm level
pub fn generate_deployment(program_string: &str) -> Result<Deployment> {
    // NOTE: we're skipping the part of imported programs
    // https://github.com/Entropy1729/snarkVM/blob/2c4e282df46ed71c809fd4b49738fd78562354ac/vm/package/deploy.rs#L149

    let (program, program_build) = build_program(program_string)?;
    let verifying_keys: IndexMap<String, VerifyingKey> = program_build
        .into_iter()
        .map(|(function_name, (_proving_key, verifying_key))| (function_name, verifying_key))
        .collect();

    Ok(Deployment {
        program,
        verifying_keys: VerifyingKeyMap {
            map: verifying_keys,
        },
    })
}

/// Basic deployment validations
pub fn verify_deployment(program: &Program, verifying_keys: VerifyingKeyMap) -> Result<()> {
    // Ensure the deployment contains verifying keys.
    let program_id = program.id();
    ensure!(
        !verifying_keys.map.is_empty(),
        "No verifying keys present in the deployment for program '{program_id}'"
    );

    // Ensure the number of verifying keys matches the number of program functions.
    if verifying_keys.map.len() != program.functions().len() {
        bail!("The number of verifying keys does not match the number of program functions");
    }

    // Ensure the program functions are in the same order as the verifying keys.
    for ((function_name, function), candidate_name) in
        program.functions().iter().zip_eq(verifying_keys.map.keys())
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
    Ok(())
}
