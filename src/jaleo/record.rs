use super::{AddressBytes, PrivateKey, RecordEntriesMap, ViewKey};
use crate::helpers;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use anyhow::{anyhow, Result};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use digest::generic_array::GenericArray;
use serde::{
    de,
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};
use sha3::{Digest, Sha3_256};
use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct EncryptedRecord {
    pub commitment: String,
    pub ciphertext: String,
    original_size: usize,
}

impl EncryptedRecord {
    pub fn decrypt(&self, view_key: &ViewKey) -> Result<Record> {
        let mut plaintext: Vec<u8> = Vec::new();
        let ciphertext_bytes = hex::decode(&self.ciphertext)?;
        ciphertext_bytes.chunks_exact(16).for_each(|chunk| {
            let mut block = GenericArray::clone_from_slice(chunk);
            view_key.decrypt_block(&mut block);
            plaintext.extend_from_slice(&block);
        });

        let record =
            serde_json::from_slice(plaintext.get(..self.original_size).ok_or_else(|| {
                anyhow!("Error getting the original-size plaintext when decrypting a record")
            })?)?;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Record {
    #[serde(deserialize_with = "deserialize_address")]
    pub owner: AddressBytes,
    #[serde(deserialize_with = "deserialize_gates")]
    pub gates: u64,
    pub data: RecordEntriesMap,
    #[serde(deserialize_with = "deserialize_field_element")]
    pub nonce: ConstraintF,
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<AddressBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let primitive_address = String::deserialize(deserializer)?;
    Ok(helpers::to_address(primitive_address))
}

fn deserialize_gates<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let gates_str = String::deserialize(deserializer)?;
    let gates_value = gates_str.trim_end_matches("u64");
    str::parse::<u64>(gates_value).map_err(de::Error::custom)
}

fn deserialize_field_element<'de, D>(deserializer: D) -> Result<ConstraintF, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded_nonce = String::deserialize(deserializer)?;
    let nonce_str = hex::decode(encoded_nonce).map_err(de::Error::custom)?;

    simpleworks::fields::deserialize_field_element(nonce_str).map_err(de::Error::custom)
}

fn sha3_hash(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let bytes = hasher.finalize().to_vec();
    hex::encode(bytes)
}

impl Record {
    pub fn new(
        owner: AddressBytes,
        gates: u64,
        data: RecordEntriesMap,
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
            data,
            nonce: nonce_value,
        }
    }

    /// This method exists just to conform to the SnarkVM API.
    pub fn owner(&self) -> AddressBytes {
        self.owner
    }

    /// This method exists just to conform to the SnarkVM API.
    pub fn gates(&self) -> u64 {
        self.gates
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
    pub fn encrypt(&self, view_key: &ViewKey) -> Result<EncryptedRecord> {
        let mut encrypted_record_bytes: Vec<u8> = Vec::new();
        let record_bytes = self.to_bytes()?;

        record_bytes.chunks_exact(16).for_each(|chunk| {
            let mut block = GenericArray::clone_from_slice(chunk);
            view_key.encrypt_block(&mut block);
            encrypted_record_bytes.extend_from_slice(&block);
        });

        let mut extended_chunk = [0_u8; 16];
        for (extended_chunk_byte, chunk_byte) in extended_chunk
            .iter_mut()
            .zip(record_bytes.chunks_exact(16).remainder())
        {
            *extended_chunk_byte = *chunk_byte;
        }
        let mut block = GenericArray::clone_from_slice(&extended_chunk);
        view_key.encrypt_block(&mut block);
        encrypted_record_bytes.extend_from_slice(&block);

        Ok(EncryptedRecord {
            commitment: self.commitment()?,
            ciphertext: hex::encode(encrypted_record_bytes),
            original_size: record_bytes.len(),
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_string(self)?.as_bytes().to_vec())
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
            std::str::from_utf8(&self.owner).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("gates", &format!("{}u64", self.gates))?;
        state.serialize_field("data", &self.data)?;

        let nonce = serialize_field_element(self.nonce).map_err(serde::ser::Error::custom)?;
        state.serialize_field("nonce", &hex::encode(nonce))?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::jaleo::{AddressBytes, RecordEntriesMap};

    use super::Record;
    use aes::cipher::KeyInit;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;
    use digest::generic_array::GenericArray;
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
        let data = RecordEntriesMap::default();
        let record = Record::new(address, gates, data, None);

        assert!(record.commitment().is_ok());
    }

    #[test]
    fn test_serialize_record() {
        let (address_string, address) = address(0);
        let gates = 0_u64;
        let data = RecordEntriesMap::default();
        let record = Record::new(address, gates, data, None);
        let nonce = serialize_field_element(record.nonce).unwrap();

        let record_string = serde_json::to_string(&record).unwrap();

        assert_eq!(
            record_string,
            format!(
                "{{\"owner\":\"{address_string}\",\"gates\":\"{gates}u64\",\"data\":{{}},\"nonce\":\"{}\"}}",
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
            r#"{{"owner": "{address}","gates": "0u64","data": {{}},"nonce": "{encoded_nonce}"}}"#
        );
        println!("record_str: {}", record_str);
        let record: Record = serde_json::from_str(record_str).unwrap();

        assert_eq!(record.owner, address.as_bytes());
        assert_eq!(record.gates, 0);
        assert_eq!(record.data, RecordEntriesMap::default());
        assert_eq!(record.nonce, nonce);
    }

    #[test]
    fn test_bincode_serialization() {
        let (_address_string, address) = address(0);
        let gates = 0_u64;
        let data = RecordEntriesMap::default();
        let record = Record::new(address, gates, data, None);

        assert!(bincode::serialize(&record).is_ok());
    }

    #[test]
    fn test_bincode_deserialization() {
        let (_address_string, address) = address(0);
        let gates = 0_u64;
        let data = RecordEntriesMap::default();
        let record = Record::new(address, gates, data, None);
        let serialized_record = bincode::serialize(&record).unwrap();

        assert!(bincode::deserialize::<Record>(&serialized_record).is_ok());
    }

    #[test]
    fn test_record_uniqueness() {
        let (_owner_str, owner) = address(0);
        let record1 = Record::new(owner, 0, RecordEntriesMap::default(), None);
        let record2 = Record::new(owner, 0, RecordEntriesMap::default(), None);

        assert_ne!(record1.commitment().unwrap(), record2.commitment().unwrap());
    }

    #[test]
    fn test_record_encryption() {
        let (_owner_str, owner) = address(0);
        let record = Record::new(owner, 0, RecordEntriesMap::default(), None);
        let encrypted_record = record
            .encrypt(&aes::Aes128::new(&GenericArray::from([0_u8; 16])))
            .unwrap();

        assert_eq!(encrypted_record.commitment, record.commitment().unwrap());
    }

    #[test]
    fn test_record_decryption() {
        let (_owner_str, owner) = address(0);
        let view_key = aes::Aes128::new(&GenericArray::from([0_u8; 16]));
        let record = Record::new(owner, 0, RecordEntriesMap::default(), None);
        let encrypted_record = record.encrypt(&view_key).unwrap();
        let decrypted_record = encrypted_record.decrypt(&view_key).unwrap();

        assert_eq!(decrypted_record, record);
    }
}
