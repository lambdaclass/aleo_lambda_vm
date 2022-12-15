use anyhow::{anyhow, Result};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use serde::{
    de,
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};
use sha3::{Digest, Sha3_256};
use simpleworks::{
    fields::deserialize_field_element,
    fields::serialize_field_element,
    gadgets::ConstraintF,
    types::value::{Address, RecordEntriesMap},
};
use std::fmt::Display;

use super::{PrivateKey, ViewKey};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Record {
    #[serde(deserialize_with = "deserialize_address")]
    pub owner: Address,
    #[serde(deserialize_with = "deserialize_gates")]
    pub gates: u64,
    pub entries: RecordEntriesMap,
    #[serde(deserialize_with = "deserialize_constraint_f")]
    pub nonce: ConstraintF,
}

fn sha3_hash(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let bytes = hasher.finalize().to_vec();
    hex::encode(&bytes)
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let address_str = String::deserialize(deserializer)?;

    let mut address = [0_u8; 63];
    for (sender_address_byte, address_string_byte) in address.iter_mut().zip(address_str.as_bytes())
    {
        *sender_address_byte = *address_string_byte;
    }

    Ok(address)
}

fn deserialize_gates<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let gates_str = String::deserialize(deserializer)?;
    let gates_value = gates_str.trim_end_matches("u64");
    str::parse::<u64>(gates_value).map_err(de::Error::custom)
}

fn deserialize_constraint_f<'de, D>(deserializer: D) -> Result<ConstraintF, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded_nonce = String::deserialize(deserializer)?;
    let nonce_str = hex::decode(encoded_nonce).map_err(de::Error::custom)?;

    deserialize_field_element(nonce_str).map_err(de::Error::custom)
}

impl Record {
    pub fn new(owner: Address, gates: u64, entries: RecordEntriesMap) -> Self {
        Self {
            owner,
            gates,
            entries,
            nonce: ConstraintF::rand(&mut thread_rng()),
        }
    }

    /// Returns the record commitment. This is a Pedersen hash underneath.
    // This function will return a String while we are using sha3 for hashing.
    // In the future it should be using a hash function that returns a field
    // element.
    pub fn commitment(&self) -> Result<String> {
        let record_string = serde_json::to_string(self)?;
        let mut record_bytes = serialize_field_element(self.nonce)?;
        record_bytes.extend_from_slice(record_string.as_bytes());
        Ok(sha3_hash(&record_bytes))
    }

    /// Returns the record serial number.
    // This function will return a String while we are using sha3 for hashing.
    // In the future the serial number will be generated using the private key.
    pub fn serial_number(&self, _private_key: &PrivateKey) -> Result<String> {
        Ok(sha3_hash(
            &hex::decode(self.commitment()?).map_err(|e| anyhow!("{e:?}"))?,
        ))
    }

    pub fn is_owner(&self, address: &Address, _view_key: &ViewKey) -> bool {
        self.owner == *address
    }

    pub fn decrypt(&self, _view_key: &ViewKey) -> Result<Self> {
        Ok(self.clone())
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let record = serde_json::to_string_pretty(self).map_err(std::fmt::Error::custom)?;
        write!(f, "{}", record)
    }
}

impl Serialize for Record {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let fields = 4;
        let mut state = serializer.serialize_struct("Record", fields)?;
        state.serialize_field(
            "owner",
            &bytes_to_string(&self.owner).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("gates", &format!("{}u64", self.gates))?;
        state.serialize_field("entries", &self.entries)?;

        let nonce = serialize_field_element(self.nonce).map_err(serde::ser::Error::custom)?;
        state.serialize_field("nonce", &hex::encode(nonce))?;
        state.end()
    }
}

fn bytes_to_string(bytes: &[u8]) -> Result<String> {
    let mut o = String::with_capacity(63);
    for byte in bytes {
        let c = char::from_u32(<u8 as std::convert::Into<u32>>::into(*byte))
            .ok_or("Error converting u8 into u32")
            .map_err(|e| anyhow!("{e}"))?;
        o.push(c);
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::Record;
    use crate::jaleo::record::bytes_to_string;
    use simpleworks::{
        fields::serialize_field_element,
        types::value::{Address, RecordEntriesMap},
    };

    fn address(n: u64) -> (String, Address) {
        let mut address_bytes = [0_u8; 63];
        let address_string =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_string, address_bytes)
    }

    #[test]
    fn test_record_commitment() {
        let (_address_string, address) = address(0);
        let gates = 0_u64;
        let entries = RecordEntriesMap::default();
        let record = Record::new(address, gates, entries);

        assert!(record.commitment().is_ok());
    }

    #[test]
    fn test_serialize_record() {
        let (address_string, address) = address(0);
        let gates = 0_u64;
        let entries = RecordEntriesMap::default();
        let record = Record::new(address, gates, entries);
        let nonce = serialize_field_element(record.nonce).unwrap();

        let record_string = serde_json::to_string(&record).unwrap();

        assert_eq!(
            record_string,
            format!(
                "{{\"owner\":\"{address_string}\",\"gates\":\"{gates}u64\",\"entries\":{{}},\"nonce\":\"{}\"}}",
                hex::encode(nonce),
            )
        );
    }

    #[test]
    fn test_record_uniqueness() {
        let (_owner_str, owner) = address(0);
        let record1 = Record::new(owner, 0, RecordEntriesMap::default());
        let record2 = Record::new(owner, 0, RecordEntriesMap::default());

        assert_ne!(record1.commitment().unwrap(), record2.commitment().unwrap());
    }
}
