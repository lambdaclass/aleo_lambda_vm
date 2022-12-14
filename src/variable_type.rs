use crate::jaleo::{Field, JAleoRecord};
use std::fmt::Display;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use simpleworks::types::value::SimpleworksValueType;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VariableType {
    /// The plaintext hash and (optional) plaintext.
    // Constant(ConstraintF, SimpleworksValueType),
    /// The plaintext.
    Public(SimpleworksValueType),
    /// The ciphertext.
    // TODO: Replace SimpleworksValueType with Ciphertext.
    Private(SimpleworksValueType),
    /// The serial number, and the record.
    // The serial number is an option because output records don't have serial numbers.
    Record(Option<Field>, JAleoRecord),
    // The input commitment to the external record. Note: This is **not** the record commitment.
    // ExternalRecord(ConstraintF),
}

impl VariableType {
    pub fn value(&self) -> Result<SimpleworksValueType> {
        match self {
            // XXX::Constant(_, value) => Ok(value.to_string()),
            VariableType::Public(value) | VariableType::Private(value) => Ok(value.clone()),
            VariableType::Record(
                _,
                JAleoRecord {
                    owner,
                    gates,
                    entries,
                    nonce: _,
                },
            ) => Ok(SimpleworksValueType::Record {
                owner: *owner,
                gates: *gates,
                entries: entries.clone(),
            }),
            // XXX::ExternalRecord(value) => Ok(value.to_string()),
        }
    }
}

impl Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableType::Public(v) | VariableType::Private(v) => SimpleworksValueType::fmt(v, f),
            VariableType::Record(_, v) => JAleoRecord::fmt(v, f),
        }
    }
}
