use crate::helpers;
use crate::jaleo::Record as JAleoRecord;
use anyhow::{anyhow, bail, Result};
use indexmap::IndexMap;
use serde::ser::Error;
use serde::Deserialize;
use simpleworks::gadgets::traits::ToFieldElements;
use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};
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
}

fn hashmap_to_string(hashmap: &RecordEntriesMap) -> Result<String> {
    let mut ret = String::new();
    ret.push('{');

    for (i, (k, v)) in hashmap.iter().enumerate() {
        ret.push_str(&format!("\"{}\":\"{}\"", k, v));
        if i > 0 {
            ret.push(',');
        }
    }

    ret.push('}');
    Ok(ret)
}

impl From<UserInputValueType> for String {
    fn from(value: UserInputValueType) -> Self {
        format!("{}", value)
    }
}

impl TryFrom<String> for UserInputValueType {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.ends_with("u8") {
            let v = value.trim_end_matches("u8");
            let value_int = v.parse::<u8>().map_err(|e| anyhow!("{}", e))?;
            return Ok(UserInputValueType::U8(value_int));
        } else if value.ends_with("u16") {
            let v = value.trim_end_matches("u16");
            let value_int = v.parse::<u16>().map_err(|e| anyhow!("{}", e))?;
            return Ok(UserInputValueType::U16(value_int));
        } else if value.ends_with("u32") {
            let v = value.trim_end_matches("u32");
            let value_int = v.parse::<u32>().map_err(|e| anyhow!("{}", e))?;
            return Ok(UserInputValueType::U32(value_int));
        } else if value.ends_with("u64") {
            let v = value.trim_end_matches("u64");
            let value_int = v.parse::<u64>().map_err(|e| anyhow!("{}", e))?;
            return Ok(UserInputValueType::U64(value_int));
        } else if value.ends_with("u128") {
            let v = value.trim_end_matches("u128");
            let value_int = v.parse::<u128>().map_err(|e| anyhow!("{}", e))?;
            return Ok(UserInputValueType::U128(value_int));
        } else if value.starts_with("aleo1") {
            let mut address = [0_u8; 63];
            for (sender_address_byte, address_string_byte) in
                address.iter_mut().zip(value.as_bytes())
            {
                *sender_address_byte = *address_string_byte;
            }
            return Ok(UserInputValueType::Address(address));
        } else {
            // This is the Record case, we expect it to be json
            let record = serde_json::from_str::<JAleoRecord>(&value)?;
            return Ok(UserInputValueType::Record(record));
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
                entries,
                nonce,
            }) => {
                write!(
                    f,
                    "{{\"owner\":\"{}\",\"gates\":\"{}u64\",\"entries\":{},\"nonce\":\"{}\"}}",
                    helpers::bytes_to_string(owner).map_err(fmt::Error::custom)?,
                    gates,
                    hashmap_to_string(entries).map_err(fmt::Error::custom)?,
                    hex::encode(serialize_field_element(*nonce).map_err(fmt::Error::custom)?)
                )
            }
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
                entries: _,
                nonce: _,
            }) => {
                bail!("Converting records to field elements is not supported")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jaleo::{Record, RecordEntriesMap};

    use super::UserInputValueType;
    use ark_ff::UniformRand;
    use simpleworks::{
        fields::serialize_field_element, gadgets::ConstraintF, marlin::generate_rand,
    };

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
        let nonce = ConstraintF::rand(&mut generate_rand());
        let v = UserInputValueType::Record(Record {
            owner: address,
            gates,
            entries: RecordEntriesMap::default(),
            nonce,
        });
        let out = format!("{v}");
        assert_eq!(out, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"1u64\",\"entries\":{{}},\"nonce\":\"{}\"}}", hex::encode(serialize_field_element(nonce).unwrap())));
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

        assert_eq!(v, format!("\"\\\"{address_str}\\\"\""));
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
        let nonce = ConstraintF::rand(&mut generate_rand());
        let data = UserInputValueType::Record(Record {
            owner: address,
            gates: 0,
            entries: RecordEntriesMap::default(),
            nonce,
        });

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"0u64\",\"entries\":{{}},\"nonce\":\"{}\"}}", hex::encode(serialize_field_element(nonce).unwrap())));
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
        let mut entries = RecordEntriesMap::new();
        entries.insert("amount".to_owned(), UserInputValueType::U64(0));
        let nonce = ConstraintF::rand(&mut generate_rand());
        let data = UserInputValueType::Record(Record {
            owner: address,
            gates: 0,
            entries,
            nonce,
        });

        let v = serde_json::to_string(&data).unwrap();

        assert_eq!(v, format!("{{\"owner\":\"aleo1ecw94zggphqkpdsjhfjutr9p33nn9tk2d34tz23t29awtejupugq4vne6m\",\"gates\":\"0u64\",\"entries\":{{\"amount\":\"0u64\"}},\"nonce\":\"{}\"}}", hex::encode(serialize_field_element(nonce).unwrap())));
    }
}
