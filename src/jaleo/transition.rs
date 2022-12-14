use crate::variable_type::VariableType;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transition {
    // /// The transition ID.
    // id: String,
    /// The program ID.
    pub program_id: String,
    /// The function name.
    pub function_name: String,
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
    pub fn output_records(&self) -> Vec<VariableType> {
        self.outputs
            .clone()
            .into_iter()
            .filter(|o| matches!(o, VariableType::Record(..)))
            .collect()
    }

    pub fn origins(&self) -> Vec<String> {
        self.input_records()
            .iter()
            .filter_map(|r| {
                if let VariableType::Record(record) = r {
                    record.commitment().ok()
                } else {
                    None
                }
            })
            .collect()
    }

    fn input_records(&self) -> Vec<VariableType> {
        self.inputs
            .clone()
            .into_iter()
            .filter(|o| matches!(o, VariableType::Record(..)))
            .collect()
    }
}
