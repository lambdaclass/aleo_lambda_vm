use crate::CircuitIOType;

use super::{AddressGadget, UInt64Gadget};
use ark_r1cs_std::{prelude::EqGadget, R1CSVar};
use indexmap::IndexMap;
use snarkvm::prelude::{Group, Testnet3};

pub type VMRecordEntriesMap = IndexMap<String, CircuitIOType>;

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: AddressGadget,
    pub gates: UInt64Gadget,
    // custom fields
    pub entries: VMRecordEntriesMap,
    pub nonce: Option<Group<Testnet3>>,
}

impl Record {
    pub fn new(
        owner: AddressGadget,
        gates: UInt64Gadget,
        entries: VMRecordEntriesMap,
        nonce: Option<Group<Testnet3>>,
    ) -> Self {
        Self {
            owner,
            gates,
            entries,
            nonce,
        }
    }
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        let mut entries_are_equal = true;
        for ((self_k, self_v), (other_k, other_v)) in self.entries.iter().zip(&other.entries) {
            entries_are_equal &= {
                let values_are_equal = match (self_v, other_v) {
                    (CircuitIOType::SimpleUInt8(self_v), CircuitIOType::SimpleUInt8(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt16(self_v), CircuitIOType::SimpleUInt16(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt32(self_v), CircuitIOType::SimpleUInt32(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt64(self_v), CircuitIOType::SimpleUInt64(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleRecord(self_v), CircuitIOType::SimpleRecord(other_v)) => {
                        Record::eq(self_v, other_v)
                    }
                    (
                        CircuitIOType::SimpleAddress(self_v),
                        CircuitIOType::SimpleAddress(other_v),
                    ) => match self_v.is_eq(other_v) {
                        Ok(v) => v.value().unwrap_or(false),
                        Err(_) => false,
                    },
                    (_, _) => false,
                };
                let keys_are_equal = *self_k == *other_k;
                values_are_equal && keys_are_equal
            }
        }
        self.owner.value() == other.owner.value()
            && self.gates.value() == other.gates.value()
            // && self.nonce == other.nonce
            && entries_are_equal
    }
}

impl Eq for Record {}
