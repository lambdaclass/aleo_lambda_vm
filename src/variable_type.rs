use crate::jaleo::{Field, Record, UserInputValueType};
use std::fmt::Display;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VariableType {
    /// The plaintext hash and (optional) plaintext.
    // Constant(ConstraintF, UserInputValueType),
    /// The plaintext.
    Public(UserInputValueType),
    /// The ciphertext.
    // TODO: Replace UserInputValueType with Ciphertext.
    Private(UserInputValueType),
    /// The serial number, and the record.
    // The serial number is an option because output records don't have serial numbers.
    Record(Option<Field>, Record),
    // The input commitment to the external record. Note: This is **not** the record commitment.
    // ExternalRecord(ConstraintF),
}

impl VariableType {
    pub fn value(&self) -> Result<UserInputValueType> {
        match self {
            // XXX::Constant(_, value) => Ok(value.to_string()),
            VariableType::Public(value) | VariableType::Private(value) => Ok(value.clone()),
            VariableType::Record(
                _,
                Record {
                    owner,
                    gates,
                    entries,
                    nonce,
                },
            ) => Ok(UserInputValueType::Record(Record {
                owner: *owner,
                gates: *gates,
                entries: entries.clone(),
                nonce: *nonce,
            })),
            // XXX::ExternalRecord(value) => Ok(value.to_string()),
        }
    }
}

impl Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableType::Public(v) | VariableType::Private(v) => UserInputValueType::fmt(v, f),
            VariableType::Record(_, v) => Record::fmt(v, f),
        }
    }
}
