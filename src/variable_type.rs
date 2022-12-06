use std::fmt::Display;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use simpleworks::types::value::SimpleworksValueType;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VariableType {
    /// The plaintext hash and (optional) plaintext.
    // Constant(ConstraintF, SimpleworksValueType),
    /// The plaintext hash and (optional) plaintext.
    Public(String, SimpleworksValueType),
    /// The ciphertext hash and (optional) ciphertext.
    // TODO: Replace SimpleworksValueType with Ciphertext.
    Private(String, SimpleworksValueType),
    /// The serial number, and the origin of the record.
    Record(String, String, SimpleworksValueType),
    // The input commitment to the external record. Note: This is **not** the record commitment.
    // ExternalRecord(ConstraintF),
}

impl VariableType {
    pub fn value(&self) -> Result<&SimpleworksValueType> {
        match self {
            // XXX::Constant(_, value) => Ok(value.to_string()),
            VariableType::Public(_, value)
            | VariableType::Private(_, value)
            | VariableType::Record(_, _, value) => Ok(value),
            // XXX::ExternalRecord(value) => Ok(value.to_string()),
        }
    }
}

impl Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableType::Public(_, v)
            | VariableType::Private(_, v)
            | VariableType::Record(_, _, v) => SimpleworksValueType::fmt(v, f),
        }
    }
}
