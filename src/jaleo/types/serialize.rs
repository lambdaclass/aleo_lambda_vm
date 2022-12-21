use super::UserInputValueType;
use crate::{helpers, jaleo::Record as JAleoRecord};
use anyhow::Result;
use serde::{de, ser::SerializeStruct, Deserialize, Serialize};
use simpleworks::fields::serialize_field_element;

impl Serialize for UserInputValueType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            UserInputValueType::Record(JAleoRecord {
                owner,
                gates,
                entries,
                nonce,
            }) => {
                let mut state = serializer.serialize_struct("Record", 4)?;
                state.serialize_field(
                    "owner",
                    &helpers::bytes_to_string(owner).map_err(serde::ser::Error::custom)?,
                )?;
                state.serialize_field("gates", &format!("{gates}u64"))?;
                state.serialize_field("entries", &entries)?;
                state.serialize_field(
                    "nonce",
                    &hex::encode(
                        serialize_field_element(*nonce).map_err(serde::ser::Error::custom)?,
                    ),
                )?;
                state.end()
            }
            _ => {
                let value = format!("{}", self);
                value.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for UserInputValueType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        match value {
            serde_json::Value::String(s) => {
                if s.ends_with("u8") {
                    let value_str = s.strip_suffix("u8").ok_or_else(|| {
                        de::Error::custom(format!(
                            "Error stripping 'u8' suffix when deserializing UserInputValueType: value was {s}"
                        ))
                    })?;
                    let value = value_str.parse::<u8>().map_err(|e| {
                        de::Error::custom(format!("Error parsing trimmed 'u8' into u8: {e:?}"))
                    })?;
                    Ok(UserInputValueType::U8(value))
                } else if s.ends_with("u16") {
                    let value_str = s.strip_suffix("u16").ok_or_else(|| {
                        de::Error::custom(format!(
                            "Error stripping 'u8' suffix when deserializing UserInputValueType: value was {s}"
                        ))
                    })?;
                    let value = value_str.parse::<u16>().map_err(|e| {
                        de::Error::custom(format!("Error parsing trimmed 'u16' into u16: {e:?}"))
                    })?;
                    Ok(UserInputValueType::U16(value))
                } else if s.ends_with("u32") {
                    let value_str = s.strip_suffix("u32").ok_or_else(|| {
                        de::Error::custom(format!(
                            "Error stripping 'u8' suffix when deserializing UserInputValueType: value was {s}"
                        ))
                    })?;
                    let value = value_str.parse::<u32>().map_err(|e| {
                        de::Error::custom(format!("Error parsing trimmed 'u32' into u32: {e:?}"))
                    })?;
                    Ok(UserInputValueType::U32(value))
                } else if s.ends_with("u64") {
                    let value_str = s.strip_suffix("u64").ok_or_else(|| {
                        de::Error::custom(format!(
                            "Error stripping 'u8' suffix when deserializing UserInputValueType: value was {s}"
                        ))
                    })?;
                    let value = value_str.parse::<u64>().map_err(|e| {
                        de::Error::custom(format!("Error parsing trimmed 'u64' into u64: {e:?}"))
                    })?;
                    Ok(UserInputValueType::U64(value))
                } else if s.ends_with("u128") {
                    let value_str = s.strip_suffix("u128").ok_or_else(|| {
                        de::Error::custom(format!(
                            "Error stripping 'u8' suffix when deserializing UserInputValueType: value was {s}"
                        ))
                    })?;
                    let value = value_str.parse::<u128>().map_err(|e| {
                        de::Error::custom(format!("Error parsing trimmed 'u128' into u128: {e:?}"))
                    })?;
                    Ok(UserInputValueType::U128(value))
                } else if s.starts_with("aleo") {
                    let address = helpers::to_address(s);
                    Ok(UserInputValueType::Address(address))
                } else {
                    Err(de::Error::custom(format!(
                        "Invalid UserInputValueType to deserialize: {s}"
                    )))
                }
            }
            serde_json::Value::Object(o) => {
                let record: JAleoRecord = serde_json::from_value(serde_json::Value::Object(o))
                    .map_err(|e| {
                        de::Error::custom(format!(
                            "Error deserializing UserInputValueType::Record: {e:?}"
                        ))
                    })?;
                Ok(UserInputValueType::Record(record))
            }
            _ => Err(de::Error::custom(
                "Invalid UserInputValueType to deserialize",
            )),
        }
    }
}
