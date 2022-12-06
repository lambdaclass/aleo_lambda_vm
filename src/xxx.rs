use serde::{Serialize, Deserialize};
use simpleworks::types::value::SimpleworksValueType;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum XXX {
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
