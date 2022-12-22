use super::{AddressBytes, PrivateKey, RecordEntriesMap, ViewKey};
use crate::helpers;
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
    fields::deserialize_field_element, fields::serialize_field_element, gadgets::ConstraintF,
};
use std::fmt::Display;

pub type EncryptedRecord = Record;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub owner: AddressBytes,
    pub gates: u64,
    pub entries: RecordEntriesMap,
    pub nonce: ConstraintF,
}

fn sha3_hash(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let bytes = hasher.finalize().to_vec();
    hex::encode(bytes)
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let request = serde_json::Value::deserialize(deserializer)?;
        let owner_value: String = serde_json::from_value(
            request
                .get("owner")
                .ok_or_else(|| {
                    de::Error::custom("Error getting 'owner' when deserializing record")
                })?
                .clone(),
        )
        .map_err(de::Error::custom)?;
        let owner = helpers::to_address(owner_value);
        let gates_value: String = serde_json::from_value(
            request
                .get("gates")
                .ok_or_else(|| {
                    de::Error::custom("Error getting 'gates' when deserializing record")
                })?
                .clone(),
        )
        .map_err(de::Error::custom)?;
        let gates_str = gates_value.strip_suffix("u64").ok_or_else(|| {
            de::Error::custom(format!(
                "Error stripping 'gates' suffix when deserializing record: gates was {gates_value}"
            ))
        })?;
        let gates = gates_str.parse::<u64>().map_err(|e| {
            de::Error::custom(format!("Error parsing trimmed 'gates' into u64: {e:?}"))
        })?;
        let entries: RecordEntriesMap = serde_json::from_value(
            request
                .get("entries")
                .ok_or_else(|| {
                    de::Error::custom("Error getting 'entries' when deserializing record")
                })?
                .clone(),
        )
        .map_err(de::Error::custom)?;
        let nonce_value: String = serde_json::from_value(
            request
                .get("nonce")
                .ok_or_else(|| {
                    de::Error::custom("Error getting 'nonce' when deserializing record")
                })?
                .clone(),
        )
        .map_err(de::Error::custom)?;
        let nonce = deserialize_field_element(hex::decode(nonce_value).map_err(de::Error::custom)?)
            .map_err(de::Error::custom)?;
        Ok(Self::new(owner, gates, entries, Some(nonce)))
    }
}

impl Record {
    pub fn new(
        owner: AddressBytes,
        gates: u64,
        entries: RecordEntriesMap,
        nonce: Option<ConstraintF>,
    ) -> Self {
        let nonce_value = if let Some(value) = nonce {
            value
        } else {
            ConstraintF::rand(&mut thread_rng())
        };

        Self {
            owner,
            gates,
            entries,
            nonce: nonce_value,
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

    pub fn is_owner(&self, address: &AddressBytes, _view_key: &ViewKey) -> bool {
        self.owner == *address
    }

    pub fn decrypt(&self, _view_key: &ViewKey) -> Result<Self> {
        Ok(self.clone())
    }

    pub fn encrypt(&self, _view_key: &ViewKey) -> Result<EncryptedRecord> {
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
    use crate::jaleo::{AddressBytes, RecordEntriesMap};

    use super::Record;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;
    use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};

    fn address(n: u64) -> (String, AddressBytes) {
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
        let record = Record::new(address, gates, entries, None);

        assert!(record.commitment().is_ok());
    }

    #[test]
    fn test_serialize_record() {
        let (address_string, address) = address(0);
        let gates = 0_u64;
        let entries = RecordEntriesMap::default();
        let record = Record::new(address, gates, entries, None);
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
    fn test_deserialize_record() {
        let address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
        let nonce = ConstraintF::rand(&mut thread_rng());
        let encoded_nonce = &hex::encode(serialize_field_element(nonce).unwrap());
        let record_str = &format!(
            r#"{{"owner": "{address}","gates": "0u64","entries": {{}},"nonce": "{encoded_nonce}"}}"#
        );
        println!("record_str: {}", record_str);
        let record: Record = serde_json::from_str(record_str).unwrap();

        assert_eq!(record.owner, address.as_bytes());
        assert_eq!(record.gates, 0);
        assert_eq!(record.entries, RecordEntriesMap::default());
        assert_eq!(record.nonce, nonce);
    }

    #[test]
    fn test_record_uniqueness() {
        let (_owner_str, owner) = address(0);
        let record1 = Record::new(owner, 0, RecordEntriesMap::default(), None);
        let record2 = Record::new(owner, 0, RecordEntriesMap::default(), None);

        assert_ne!(record1.commitment().unwrap(), record2.commitment().unwrap());
    }
}
