use crate::helpers;
use crate::jaleo::Record as JAleoRecord;
use anyhow::{anyhow, bail, Result};
use ark_ff::ToConstraintField;
use indexmap::IndexMap;
use serde::ser::Error;
use serde::Deserialize;
use simpleworks::gadgets::traits::ToFieldElements;
use simpleworks::gadgets::ConstraintF;
use std::str::FromStr;
use std::{convert::TryFrom, fmt};

pub type Address = [u8; 63];
pub type RecordEntriesMap = IndexMap<String, UserInputValueType>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum UserInputValueType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Address(Address),
    Record(JAleoRecord),
    Boolean(bool),
    Field(ConstraintF),
}

fn hashmap_to_string(hashmap: &RecordEntriesMap) -> Result<String> {
    let mut ret = String::new();
    ret.push('{');

    for (i, (k, v)) in hashmap.iter().enumerate() {
        ret.push_str(&format!("\"{k}\":\"{v}\""));
        if i > 0 {
            ret.push(',');
        }
    }

    ret.push('}');
    Ok(ret)
}

impl From<UserInputValueType> for String {
    fn from(value: UserInputValueType) -> Self {
        format!("{value}")
    }
}

// This exists to conform to how snarkVM does things (it uses FromStr instead of TryFrom<String>)
impl FromStr for UserInputValueType {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> Result<Self> {
        UserInputValueType::try_from(string.to_owned())
    }
}

impl TryFrom<String> for UserInputValueType {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.ends_with("u8") {
            let v = value.trim_end_matches("u8");
            let value_int = v.parse::<u8>().map_err(|e| anyhow!("{}", e))?;
            Ok(UserInputValueType::U8(value_int))
        } else if value.ends_with("u16") {
            let v = value.trim_end_matches("u16");
            let value_int = v.parse::<u16>().map_err(|e| anyhow!("{}", e))?;
            Ok(UserInputValueType::U16(value_int))
        } else if value.ends_with("u32") {
            let v = value.trim_end_matches("u32");
            let value_int = v.parse::<u32>().map_err(|e| anyhow!("{}", e))?;
            Ok(UserInputValueType::U32(value_int))
        } else if value.ends_with("u64") {
            let v = value.trim_end_matches("u64");
            let value_int = v.parse::<u64>().map_err(|e| anyhow!("{}", e))?;
            Ok(UserInputValueType::U64(value_int))
        } else if value.ends_with("u128") {
            let v = value.trim_end_matches("u128");
            let value_int = v.parse::<u128>().map_err(|e| anyhow!("{}", e))?;
            Ok(UserInputValueType::U128(value_int))
        } else if value.starts_with("aleo1") {
            let mut address = [0_u8; 63];
            for (sender_address_byte, address_string_byte) in
                address.iter_mut().zip(value.as_bytes())
            {
                *sender_address_byte = *address_string_byte;
            }
            Ok(UserInputValueType::Address(address))
        } else if value == "true" {
            Ok(UserInputValueType::Boolean(true))
        } else if value == "false" {
            Ok(UserInputValueType::Boolean(false))
        } else if value.ends_with("field") {
            let v = value.trim_end_matches("field");
            let value_int = v.parse::<ConstraintF>().map_err(|e| anyhow!("{:?}", e))?;
            Ok(UserInputValueType::Field(value_int))
        } else {
            // This is the Record case, we expect it to be json
            let record = serde_json::from_str::<JAleoRecord>(&value)?;
            Ok(UserInputValueType::Record(record))
        }
    }
}

impl fmt::Display for UserInputValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserInputValueType::U8(v) => write!(f, "{v}u8"),
            UserInputValueType::U16(v) => write!(f, "{v}u16"),
            UserInputValueType::U32(v) => write!(f, "{v}u32"),
            UserInputValueType::U64(v) => write!(f, "{v}u64"),
            UserInputValueType::U128(v) => write!(f, "{v}u128"),
            UserInputValueType::Address(v) => {
                write!(
                    f,
                    "{:?}",
                    helpers::bytes_to_string(v).map_err(fmt::Error::custom)?
                )
            }
            UserInputValueType::Record(JAleoRecord {
                owner,
                gates,
                data,
                nonce,
            }) => {
                let formatted_nonce = if let Some(nonce_value) = nonce {
                    nonce_value.to_string()
                } else {
                    String::from("")
                };
                write!(
                    f,
                    "{{\"owner\":\"{}\",\"gates\":\"{}u64\",\"entries\":{},\"nonce\":\"{}\"}}",
                    helpers::bytes_to_string(owner).map_err(fmt::Error::custom)?,
                    gates,
                    hashmap_to_string(data).map_err(fmt::Error::custom)?,
                    formatted_nonce,
                )
            }
            UserInputValueType::Boolean(b) => write!(f, "{b}"),
            UserInputValueType::Field(field_element) => write!(f, "{field_element}"),
        }
    }
}

impl ToFieldElements<ConstraintF> for UserInputValueType {
    fn to_field_elements(&self) -> Result<Vec<ConstraintF>> {
        match self {
            UserInputValueType::U8(value) => value.to_field_elements(),
            UserInputValueType::U16(value) => value.to_field_elements(),
            UserInputValueType::U32(value) => value.to_field_elements(),
            UserInputValueType::U64(value) => value.to_field_elements(),
            UserInputValueType::U128(value) => value.to_field_elements(),
            UserInputValueType::Address(value) => value.to_field_elements(),
            UserInputValueType::Record(JAleoRecord {
                owner: _,
                gates: _,
                data: _,
                nonce: _,
            }) => {
                bail!("Converting records to field elements is not supported")
            }
            UserInputValueType::Boolean(b) => b
                .to_field_elements()
                .ok_or_else(|| anyhow!("Error turning bool to field elements")),
            UserInputValueType::Field(field_element) => Ok(vec![*field_element]),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        helpers,
        jaleo::{Record, RecordEntriesMap},
    };

    use super::UserInputValueType;
    use ark_ff::UniformRand;
    use snarkvm::prelude::{Group, Scalar};

    #[test]
    fn display_value() {
        let v = UserInputValueType::U8(2);
        let out = format!("{v}");
        assert_eq!(out, "2u8");
        let v = UserInputValueType::U16(3);
        let out = format!("{v}");
        assert_eq!(out, "3u16");
        let v = UserInputValueType::U32(4);
        let out = format!("{v}");
        assert_eq!(out, "4u32");
        let v = UserInputValueType::U64(5);
        let out = format!("{v}");
        assert_eq!(out, "5u64");
        let v = UserInputValueType::U128(6);
        let out = format!("{v}");
        assert_eq!(out, "6u128");
        // Address
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let v = UserInputValueType::Address(address);
        let out = format!("{v}");
        assert_eq!(out, format!("\"{address_str}\""));
        // Record
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let gates = 1_u64;
        let nonce = helpers::random_nonce();

        let v = UserInputValueType::Record(Record {
            owner: address,
            gates,
            data: RecordEntriesMap::default(),
            nonce: Some(nonce),
        });
        let out = format!("{v}");
        assert_eq!(out, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"1u64\",\"entries\":{{}},\"nonce\":\"{}\"}}", nonce));
    }

    /* Deserialize Tests */

    #[test]
    fn test_deserialize_address() {
        let address = "aleo11111111111111111111111111111111111111111111111111111111111";
        let data = format!("\"{address}\"");

        let v: UserInputValueType = serde_json::from_str(&data).unwrap();

        assert!(matches!(v, UserInputValueType::Address(_)));
        if let UserInputValueType::Address(a) = v {
            assert_eq!(a, address.as_bytes());
        }
    }

    #[test]
    fn test_deserialize_u8() {
        let v: UserInputValueType = serde_json::from_str("\"0u8\"").unwrap();

        assert!(matches!(v, UserInputValueType::U8(_)));
        if let UserInputValueType::U8(value) = v {
            assert_eq!(value, 0_u8);
        }
    }

    #[test]
    fn test_deserialize_u16() {
        let v: UserInputValueType = serde_json::from_str("\"0u16\"").unwrap();

        assert!(matches!(v, UserInputValueType::U16(_)));
        if let UserInputValueType::U16(value) = v {
            assert_eq!(value, 0_u16);
        }
    }

    #[test]
    fn test_deserialize_u32() {
        let v: UserInputValueType = serde_json::from_str("\"0u32\"").unwrap();

        assert!(matches!(v, UserInputValueType::U32(_)));
        if let UserInputValueType::U32(value) = v {
            assert_eq!(value, 0_u32);
        }
    }

    #[test]
    fn test_deserialize_u64() {
        let v: UserInputValueType = serde_json::from_str("\"0u64\"").unwrap();

        assert!(matches!(v, UserInputValueType::U64(_)));
        if let UserInputValueType::U64(value) = v {
            assert_eq!(value, 0_u64);
        }
    }

    #[test]
    fn test_deserialize_u128() {
        let v: UserInputValueType = serde_json::from_str("\"0u128\"").unwrap();

        assert!(matches!(v, UserInputValueType::U128(_)));
        if let UserInputValueType::U128(value) = v {
            assert_eq!(value, 0_u128);
        }
    }

    /* Serialize Tests */
    #[test]
    fn test_serialize_address() {
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let data = UserInputValueType::Address(address);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!(r#""{address_str}""#));
    }

    #[test]
    fn test_serialize_u8() {
        let data = UserInputValueType::U8(0);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("\"{data}\""));
    }

    #[test]
    fn test_serialize_u16() {
        let data = UserInputValueType::U16(0);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("\"{data}\""));
    }

    #[test]
    fn test_serialize_u32() {
        let data = UserInputValueType::U32(0);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("\"{data}\""));
    }

    #[test]
    fn test_serialize_u64() {
        let data = UserInputValueType::U64(0);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("\"{data}\""));
    }

    #[test]
    fn test_serialize_u128() {
        let data = UserInputValueType::U128(0);

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("\"{data}\""));
    }

    #[test]
    fn test_serialize_record_without_entries() {
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }

        let nonce = helpers::random_nonce();

        let data = UserInputValueType::Record(Record {
            owner: address,
            gates: 0,
            data: RecordEntriesMap::default(),
            nonce: Some(nonce),
        });

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"0u64\",\"data\":{{}},\"nonce\":\"{}\"}}", nonce));
    }

    #[test]
    fn test_serialize_record_with_entries() {
        let mut address = [0_u8; 63];
        let address_str = "aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m";
        for (sender_address_byte, address_string_byte) in
            address.iter_mut().zip(address_str.as_bytes())
        {
            *sender_address_byte = *address_string_byte;
        }
        let mut data = RecordEntriesMap::new();
        data.insert("amount".to_owned(), UserInputValueType::U64(0));
        let rng = &mut rand::thread_rng();
        let randomizer = Scalar::rand(rng);
        let nonce = Group::generator() * randomizer;

        let data = UserInputValueType::Record(Record {
            owner: address,
            gates: 0,
            data,
            nonce: Some(nonce),
        });

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"0u64\",\"data\":{{\"amount\":\"0u64\"}},\"nonce\":\"{}\"}}", nonce));
    }

    #[test]
    fn test_bincode_serialization() {
        let unsigned_int_8 = UserInputValueType::U8(0);
        let unsigned_int_16 = UserInputValueType::U16(0);
        let unsigned_int_32 = UserInputValueType::U32(0);
        let unsigned_int_64 = UserInputValueType::U64(0);
        let unsigned_int_128 = UserInputValueType::U128(0);

        assert!(bincode::serialize(&unsigned_int_8).is_ok());
        assert!(bincode::serialize(&unsigned_int_16).is_ok());
        assert!(bincode::serialize(&unsigned_int_32).is_ok());
        assert!(bincode::serialize(&unsigned_int_64).is_ok());
        assert!(bincode::serialize(&unsigned_int_128).is_ok());
    }

    #[test]
    fn test_bincode_deserialization() {
        let unsigned_int_8 = UserInputValueType::U8(0);
        let unsigned_int_16 = UserInputValueType::U16(0);
        let unsigned_int_32 = UserInputValueType::U32(0);
        let unsigned_int_64 = UserInputValueType::U64(0);
        let unsigned_int_128 = UserInputValueType::U128(0);

        let serialized_unsigned_int_8 = bincode::serialize(&unsigned_int_8).unwrap();
        let serialized_unsigned_int_16 = bincode::serialize(&unsigned_int_16).unwrap();
        let serialized_unsigned_int_32 = bincode::serialize(&unsigned_int_32).unwrap();
        let serialized_unsigned_int_64 = bincode::serialize(&unsigned_int_64).unwrap();
        let serialized_unsigned_int_128 = bincode::serialize(&unsigned_int_128).unwrap();

        assert_eq!(
            unsigned_int_8,
            bincode::deserialize(&serialized_unsigned_int_8).unwrap()
        );
        assert_eq!(
            unsigned_int_16,
            bincode::deserialize(&serialized_unsigned_int_16).unwrap()
        );
        assert_eq!(
            unsigned_int_32,
            bincode::deserialize(&serialized_unsigned_int_32).unwrap()
        );
        assert_eq!(
            unsigned_int_64,
            bincode::deserialize(&serialized_unsigned_int_64).unwrap()
        );
        assert_eq!(
            unsigned_int_128,
            bincode::deserialize(&serialized_unsigned_int_128).unwrap()
        );
    }
}
