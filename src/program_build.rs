use crate::FunctionKeys;
use indexmap::IndexMap;
use serde::{Serialize, ser::{self, SerializeMap, Error}, Deserialize, de};
use simpleworks::marlin::serialization::{serialize_verifying_key, serialize_proving_key, deserialize_proving_key, deserialize_verifying_key};
use std::fmt::Debug;

pub struct ProgramBuild {
    pub map: IndexMap<String, FunctionKeys>,
}

impl Serialize for ProgramBuild {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_map(Some(self.map.len()))?;
        for (k, (pk, vk)) in &self.map {
            let serialized_verifying_key =
                hex::encode(serialize_verifying_key(vk.clone()).map_err(ser::Error::custom)?);
            let serialized_proving_key =
                hex::encode(serialize_proving_key(pk.clone()).map_err(ser::Error::custom)?);
            s.serialize_entry(&k, &(serialized_proving_key, serialized_verifying_key))?;
        }
        s.end()
    }
}

impl<'de> Deserialize<'de> for ProgramBuild {
    fn deserialize<D>(deserializer: D) -> Result<ProgramBuild, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // It's called EncodedProgramBuild because its values are encoded.
        type EncodedProgramBuild = IndexMap<String, (String, String)>;

        let intermediate_verifying_key_map = EncodedProgramBuild::deserialize(deserializer)?;
        let mut verifying_key_map = IndexMap::new();
        for (k, (pk, vk)) in intermediate_verifying_key_map {
            let bytes_proving_key = hex::decode(pk).map_err(de::Error::custom)?;
            let bytes_verifying_key = hex::decode(vk).map_err(de::Error::custom)?;
            let proving_key =
                deserialize_proving_key(bytes_proving_key).map_err(de::Error::custom)?;
            let verifying_key =
                deserialize_verifying_key(bytes_verifying_key).map_err(de::Error::custom)?;
            verifying_key_map.insert(k, (proving_key, verifying_key));
        }
        Ok(ProgramBuild {
            map: verifying_key_map,
        })
    }
}

impl Debug for ProgramBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut verifying_keys = IndexMap::new();
        for (k, (pk, vk)) in self.map.iter() {
            let serialized_proving_key =
                hex::encode(serialize_proving_key(pk.clone()).map_err(std::fmt::Error::custom)?);
            let serialized_verifying_key =
                hex::encode(serialize_verifying_key(vk.clone()).map_err(std::fmt::Error::custom)?);
            verifying_keys.insert(k.clone(), (serialized_proving_key.clone(), serialized_verifying_key.clone()));
        }
        IndexMap::fmt(&verifying_keys, f)
    }
}
