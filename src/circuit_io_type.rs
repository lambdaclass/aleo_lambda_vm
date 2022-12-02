use crate::record::Record;
use anyhow::Result;
use ark_r1cs_std::R1CSVar;
use simpleworks::gadgets::{AddressGadget, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget};

pub use CircuitIOType::{
    SimpleAddress, SimpleRecord, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

#[derive(Clone, Debug)]
pub enum CircuitIOType {
    SimpleUInt8(UInt8Gadget),
    SimpleUInt16(UInt16Gadget),
    SimpleUInt32(UInt32Gadget),
    SimpleUInt64(UInt64Gadget),
    SimpleRecord(Record),
    SimpleAddress(AddressGadget),
}

impl CircuitIOType {
    pub fn value(&self) -> Result<String> {
        match self {
            SimpleUInt8(value) => Ok(value.value()?.to_string()),
            SimpleUInt16(value) => Ok(value.value()?.to_string()),
            SimpleUInt32(value) => Ok(value.value()?.to_string()),
            SimpleUInt64(value) => Ok(value.value()?.to_string()),
            SimpleRecord(value) => {
                let owner = value.owner.value()?;
                let gates = value.gates.value()?;
                Ok(format!("Record {{ owner: {}, gates: {} }}", owner, gates))
            }
            SimpleAddress(value) => Ok(value.value()?),
        }
    }
}
