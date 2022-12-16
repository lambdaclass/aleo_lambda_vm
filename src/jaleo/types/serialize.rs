use super::UserInputValueType;
use crate::{helpers, jaleo::Record as JAleoRecord};
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