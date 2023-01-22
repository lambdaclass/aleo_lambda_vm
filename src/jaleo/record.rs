use super::{Address, AddressBytes, PrivateKey, RecordEntriesMap, ViewKey};
use crate::helpers::{self};
use aes::cipher::KeyInit;
use aes_gcm::{AeadInPlace, Aes256Gcm};
use anyhow::{anyhow, Result};
use ark_std::rand::thread_rng;
use digest::generic_array::GenericArray;
use rand::Rng;
use serde::{
    de,
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};
use sha3::{Digest, Sha3_256};
use snarkvm::prelude::{Field, FromBytes, Group, Network, Scalar, Testnet3, ToBytes};
use std::{fmt::Display, str::FromStr};

/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 12;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct EncryptedRecord {
    pub commitment: String,
    pub ciphertext: String,
    pub nonce: Group<Testnet3>,
}

/*
    When someone creates a record for someone else, they have to generate a randomizer, which is a private key,
    and its corresponding public key, the nonce. This way, they encrypt the record using the randomizer plus the address
    of the record's owner. When the owner wants to decrypt, they use their view and the nonce (which is a published part of
    the record) to decrypt.

    So far, the only thing needed for encryption/decryption is the randomizer/nonce. Where do the transition public key and
    the transition view key show up?

    The transition view key is used to generate the randomizer for every output record in the transition. The way this is done is
    simply hash(tvk || record_index), where the `record_index` is just the index of the output record in the list of output_records.

    The transition public key seems to be used to derive the serial number for records later on, though I'm not entirely sure.

    What we are going to do for now, is when someone generates a transaction, they just sample a random number as the randomizer.
    This is probably not cryptographically secure, etc, but it'll work well for us. This way we can get rid of the whole transition
    view key stuff.
*/

impl EncryptedRecord {
    pub fn decrypt(&self, view_key: &ViewKey) -> Result<Record> {
        let record_view_key = (**view_key * &self.nonce).to_x_coordinate();

        // The first 32 bytes are the record's nonce.
        let ciphertext = hex::decode(&self.ciphertext)?[32..].to_vec();

        decrypt_from_record_view_key(&record_view_key, &ciphertext)
    }

    pub fn is_owner(&self, address: &Address, view_key: &ViewKey) -> bool {
        let vm_address = crate::helpers::to_address(address.to_string());
        if let Ok(decrypted_record) = self.decrypt(view_key) {
            return decrypted_record.owner == vm_address;
        }

        false
    }

    pub fn decrypt_from_ciphertext(view_key: &ViewKey, ciphertext: &str) -> Result<Record> {
        let decoded = hex::decode(&ciphertext)?;
        let nonce_bytes = decoded[..32].to_vec();
        let ciphertext = decoded[32..].to_vec();

        let nonce = Group::<Testnet3>::from_bytes_le(&nonce_bytes)?;
        let record_view_key = (**view_key * &nonce).to_x_coordinate();

        decrypt_from_record_view_key(&record_view_key, &ciphertext)
    }
}

fn decrypt_from_record_view_key(
    record_view_key: &Field<Testnet3>,
    ciphertext: &[u8],
) -> Result<Record> {
    let mut hasher = Sha3_256::new();
    hasher.update(record_view_key.to_bytes_le()?);
    let key = hasher.finalize().to_vec();

    let key = GenericArray::from_slice(&key);
    let aead = Aes256Gcm::new(key);

    let iv = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
    let tag = GenericArray::from_slice(&ciphertext[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH]);

    let mut plaintext = Vec::with_capacity(ciphertext.len() - AES_IV_PLUS_TAG_LENGTH);
    plaintext.extend(&ciphertext[AES_IV_PLUS_TAG_LENGTH..]);

    aead.decrypt_in_place_detached(iv, &EMPTY_BYTES, &mut plaintext, tag)
        .unwrap();

    let record = serde_json::from_slice(&plaintext)?;
    Ok(record)
}

impl FromStr for EncryptedRecord {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // let mut ciphertext_with_nonce = vec![];
        // ciphertext_with_nonce.extend_from_slice(nonce_bytes);
        // ciphertext_with_nonce.extend_from_slice(&ciphertext);

        Ok(Self {
            commitment: String::from(""),
            ciphertext: String::from(""),
            nonce: helpers::random_nonce(),
        })

        // let (x, y) = s
        //     .strip_prefix('(')
        //     .and_then(|s| s.strip_suffix(')'))
        //     .and_then(|s| s.split_once(','))
        //     .ok_or(ParsePointError)?;

        // let x_fromstr = x.parse::<i32>().map_err(|_| ParsePointError)?;
        // let y_fromstr = y.parse::<i32>().map_err(|_| ParsePointError)?;

        // Ok(Point { x: x_fromstr, y: y_fromstr })
    }
}

// impl TryFrom<&Vec<u8>> for EncryptedRecord {
//     type Error = anyhow::Error;

//     fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
//         let commitment_bytes = bytes
//             .get(..64)
//             .ok_or_else(|| anyhow!("Error getting the commitment"))?;
//         let mut ciphertext_bytes = vec![];

//         let number_of_blocks = (bytes.len() - 64) / 16;
//         for i in 0..number_of_blocks {
//             for j in 0..16 {
//                 ciphertext_bytes.push(
//                     *bytes
//                         .get(64 + i * 16 + j)
//                         .ok_or_else(|| anyhow!("Error getting the ciphertext"))?,
//                 );
//             }
//         }

//         let mut original_size_bytes: [u8; 8] = [0; 8];
//         for i in 0..8 {
//             *original_size_bytes
//                 .get_mut(i)
//                 .ok_or_else(|| anyhow!("Error storing original size byte"))? = *bytes
//                 .get(bytes.len() - 8 + i)
//                 .ok_or_else(|| anyhow!("Error getting original size"))?;
//         }

//         let commitment = String::from_utf8(commitment_bytes.to_vec())?;
//         let mut ciphertext = String::from_utf8(ciphertext_bytes.to_vec())?;

//         let original_size =
//             usize::from_str_radix(&String::from_utf8(original_size_bytes.to_vec())?, 16)?;

//         ciphertext.push_str(&hex::encode(format!("{original_size:08x}")));

//         Ok(Self {
//             commitment,
//             ciphertext,
//             original_size,
//         })
//     }
// }

impl Display for EncryptedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ciphertext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Record {
    #[serde(deserialize_with = "deserialize_address")]
    pub owner: AddressBytes,
    #[serde(deserialize_with = "deserialize_gates")]
    pub gates: u64,
    pub data: RecordEntriesMap,
    // The reason the nonce is optional is that it gets decided once someone
    // encrypts the record for the first time, because its value is completely tied to
    // the randomizer that is used for encryption (the nonce is just g^randomizer).
    // Because of this, when someone calls `Record::new`, they don't know the nonce,
    // they will know it after calling `encrypt` with a randomizer.
    pub nonce: Option<Group<Testnet3>>,
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
        nonce: Option<Group<Testnet3>>,
    ) -> Self {
        Self {
            owner,
            gates,
            data,
            nonce,
        }
    }

    pub fn new_from_aleo_address(
        owner: String,
        gates: u64,
        data: RecordEntriesMap,
        nonce: Option<Group<Testnet3>>,
    ) -> Self {
        let vm_address = crate::helpers::to_address(owner);

        Self {
            owner: vm_address,
            gates,
            data,
            nonce,
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
        let record_bytes = self.to_bytes()?;
        // let mut record_bytes = serialize_field_element(self.nonce)?;
        // record_bytes.extend_from_slice(record_string.as_bytes());
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

    /// Encrypting takes a mutable reference because the act of encrypting is what decides the nonce
    /// of the record which was previously None, so we mutate it.
    pub fn encrypt(&mut self, randomizer: Scalar<Testnet3>) -> Result<EncryptedRecord> {
        let address_string = String::from_utf8(self.owner.to_vec()).unwrap();
        let address = Address::from_str(&address_string).unwrap();
        let record_nonce = Testnet3::g_scalar_multiply(&randomizer);
        self.nonce = Some(record_nonce);

        let record_view_key = (*address * randomizer).to_x_coordinate();

        let mut hasher = Sha3_256::new();
        hasher.update(record_view_key.to_bytes_le()?);
        let key = hasher.finalize().to_vec();

        let key = GenericArray::from_slice(&key);
        let aead = Aes256Gcm::new(key);

        let mut iv = [0u8; AES_IV_LENGTH];
        thread_rng().fill(&mut iv);

        let nonce = GenericArray::from_slice(&iv);

        let message = serde_json::to_vec(self)?;
        let message_length = message.len();
        let mut out = Vec::with_capacity(message_length);
        out.extend(message);

        let ciphertext = {
            let tag = aead
                .encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out)
                .unwrap();
            let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + message_length);
            output.extend(&iv);
            output.extend(tag);
            output.extend(out);
            output
        };

        let nonce_bytes = record_nonce.to_bytes_le()?;

        let mut ciphertext_with_nonce = vec![];
        ciphertext_with_nonce.extend_from_slice(&nonce_bytes);
        ciphertext_with_nonce.extend_from_slice(&ciphertext);

        Ok(EncryptedRecord {
            commitment: self.commitment()?,
            ciphertext: hex::encode(ciphertext_with_nonce),
            nonce: record_nonce,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_string(self)?.as_bytes().to_vec())
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let record = serde_json::to_string_pretty(self).map_err(std::fmt::Error::custom)?;
        write!(f, "{record}")
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

        state.serialize_field("nonce", &self.nonce)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        helpers,
        jaleo::{Address, AddressBytes, PrivateKey, RecordEntriesMap, ViewKey},
    };

    use super::{decrypt_from_record_view_key, EncryptedRecord, Record};
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;
    use indexmap::IndexMap;
    use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};
    use snarkvm::prelude::Scalar;

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

    // #[test]
    // fn test_serialize_record() {
    //     let (address_string, address) = address(0);
    //     let gates = 0_u64;
    //     let data = RecordEntriesMap::default();
    //     let record = Record::new(address, gates, data, None);
    //     let nonce = serialize_field_element(record.nonce).unwrap();

    //     let record_string = serde_json::to_string(&record).unwrap();

    //     assert_eq!(
    //         record_string,
    //         format!(
    //             "{{\"owner\":\"{address_string}\",\"gates\":\"{gates}u64\",\"data\":{{}},\"nonce\":\"{}\"}}",
    //             hex::encode(nonce),
    //         )
    //     );
    // }

    // #[test]
    // fn test_deserialize_record() {
    //     let address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
    //     let nonce = ConstraintF::rand(&mut thread_rng());
    //     let encoded_nonce = &hex::encode(serialize_field_element(nonce).unwrap());
    //     let record_str = &format!(
    //         r#"{{"owner": "{address}","gates": "0u64","data": {{}},"nonce": "{encoded_nonce}"}}"#
    //     );
    //     let record: Record = serde_json::from_str(record_str).unwrap();

    //     assert_eq!(record.owner, address.as_bytes());
    //     assert_eq!(record.gates, 0);
    //     assert_eq!(record.data, RecordEntriesMap::default());
    //     assert_eq!(record.nonce, nonce);
    // }

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
        let record1 = Record::new(
            owner,
            0,
            RecordEntriesMap::default(),
            Some(helpers::random_nonce()),
        );
        let record2 = Record::new(
            owner,
            0,
            RecordEntriesMap::default(),
            Some(helpers::random_nonce()),
        );

        assert_ne!(record1.commitment().unwrap(), record2.commitment().unwrap());
    }

    #[test]
    fn test_record_encryption_and_decryption() {
        let rng = &mut rand::thread_rng();
        let private_key = PrivateKey::new(rng).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let address = Address::try_from(&view_key).unwrap();

        let address_string = address.to_string();
        let mut address = [0_u8; 63];
        for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }

        let mut record = Record::new(address, 1, IndexMap::new(), None);
        let randomizer = Scalar::rand(rng);

        let encrypted = record.encrypt(randomizer).unwrap();
        let decrypted = encrypted.decrypt(&view_key).unwrap();
        assert_eq!(decrypted, record);
    }

    #[test]
    fn test_record_decryption_from_ciphertext() {
        let rng = &mut rand::thread_rng();
        let private_key = PrivateKey::new(rng).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let address = Address::try_from(&view_key).unwrap();

        let address_string = address.to_string();
        let mut address = [0_u8; 63];
        for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }

        let mut record = Record::new(address, 1, IndexMap::new(), None);
        let randomizer = Scalar::rand(rng);

        let encrypted = record.encrypt(randomizer).unwrap();
        let ciphertext = encrypted.ciphertext;
        let decrypted = EncryptedRecord::decrypt_from_ciphertext(&view_key, &ciphertext).unwrap();

        assert_eq!(decrypted, record);
    }
}
