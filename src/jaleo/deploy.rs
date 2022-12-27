use super::{Identifier, Program};
use crate::build_program;
use anyhow::Result;
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
use std::fmt::Debug;

#[derive(Clone)]
pub struct VerifyingKeyMap {
    pub map: IndexMap<Identifier, VerifyingKey>,
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
        type EncodedVerifyingKeyMap = IndexMap<Identifier, String>;

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
    let verifying_keys: IndexMap<Identifier, VerifyingKey> = program_build
        .map
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
