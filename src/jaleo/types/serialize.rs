use super::UserInputValueType;
use crate::jaleo::Record as JAleoRecord;
use anyhow::Result;
use serde::{ser::SerializeStruct, Serialize};
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
                data,
                nonce,
            }) => {
                let mut state = serializer.serialize_struct("Record", 4)?;
                state.serialize_field(
                    "owner",
                    std::str::from_utf8(owner).map_err(serde::ser::Error::custom)?,
                )?;
                state.serialize_field("gates", &format!("{gates}u64"))?;
                state.serialize_field("data", &data)?;
                state.serialize_field(
                    "nonce",
                    &hex::encode(
                        serialize_field_element(*nonce).map_err(serde::ser::Error::custom)?,
                    ),
                )?;
                state.end()
            }
            UserInputValueType::Address(address) => {
                let value = std::str::from_utf8(address).map_err(serde::ser::Error::custom)?;
                value.serialize(serializer)
            }
            _ => {
                let value = format!("{}", self);
                value.serialize(serializer)
            }
        }
    }
}
