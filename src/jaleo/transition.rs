use super::{EncryptedRecord, Identifier, ProgramID};
use crate::variable_type::VariableType;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transition {
    // /// The transition ID.
    // id: String,
    /// The program ID.
    pub program_id: ProgramID,
    /// The function name.
    pub function_name: Identifier,
    /// The transition inputs.
    pub inputs: Vec<VariableType>,
    /// The transition outputs.
    pub outputs: Vec<VariableType>,
    // /// The inputs for finalize.
    // finalize: Option<Vec<Value>>,
    /// The transition proof.
    pub proof: String,
    // /// The transition public key.
    // tpk: Group,
    // /// The transition commitment.
    // tcm: Field,
    /// The network fee.
    pub fee: i64,
}

impl Transition {
    pub fn output_records(&self) -> Vec<(String, EncryptedRecord)> {
        self.outputs
            .clone()
            .into_iter()
            .filter_map(|o| {
                if let VariableType::EncryptedRecord((commitment, encrypted_record)) = o {
                    Some((commitment, encrypted_record))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn origins(&self) -> Vec<String> {
        self.input_records()
            .iter()
            .filter_map(|r| {
                if let VariableType::Record(_serial_number, record) = r {
                    record.commitment().ok()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn input_records(&self) -> Vec<VariableType> {
        self.inputs
            .clone()
            .into_iter()
            .filter(|o| matches!(o, VariableType::Record(..)))
            .collect()
    }

    pub fn serial_numbers(&self) -> Vec<String> {
        self.inputs
            .iter()
            .filter_map(|transition| {
                if let VariableType::Record(serial_number, _record) = transition {
                    serial_number.clone()
                } else {
                    None
                }
            })
            .collect()
    }

    // The following functions are essentially member getters implemented
    // to comply with SnarkVM's API (where fields were private)

    pub fn fee(&self) -> &i64 {
        &self.fee
    }

    pub fn program_id(&self) -> &ProgramID {
        &self.program_id
    }

    pub fn outputs(&self) -> &Vec<VariableType> {
        &self.outputs
    }

    pub fn function_name(&self) -> &Identifier {
        &self.function_name
    }
}
