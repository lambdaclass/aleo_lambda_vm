use crate::record::Record;
use anyhow::Result;
use ark_r1cs_std::{prelude::Boolean, R1CSVar};
use simpleworks::gadgets::{
    traits::IsWitness, AddressGadget, ConstraintF, FieldGadget, Int8Gadget, UInt16Gadget,
    UInt32Gadget, UInt64Gadget, UInt8Gadget,
};

pub use CircuitIOType::{
    SimpleAddress, SimpleBoolean, SimpleField, SimpleInt8, SimpleRecord, SimpleUInt16,
    SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

#[derive(Clone, Debug)]
pub enum CircuitIOType {
    SimpleUInt8(UInt8Gadget),
    SimpleUInt16(UInt16Gadget),
    SimpleUInt32(UInt32Gadget),
    SimpleUInt64(UInt64Gadget),
    SimpleInt8(Int8Gadget),
    SimpleRecord(Record),
    SimpleAddress(AddressGadget),
    SimpleBoolean(Boolean<ConstraintF>),
    SimpleField(FieldGadget),
}

impl CircuitIOType {
    pub fn value(&self) -> Result<String> {
        match self {
            SimpleUInt8(value) => Ok(value.value()?.to_string()),
            SimpleInt8(value) => Ok(value.value()?.to_string()),
            SimpleUInt16(value) => Ok(value.value()?.to_string()),
            SimpleUInt32(value) => Ok(value.value()?.to_string()),
            SimpleUInt64(value) => Ok(value.value()?.to_string()),
            SimpleRecord(value) => {
                let owner = value.owner.value()?;
                let gates = value.gates.value()?;
                // TODO: print the entries map here as well.
                Ok(format!("Record {{ owner: {owner}, gates: {gates} }}"))
            }
            SimpleAddress(value) => Ok(value.value()?),
            SimpleBoolean(value) => Ok(value.value()?.to_string()),
            CircuitIOType::SimpleField(value) => Ok(value.value()?.to_string()),
        }
    }

    pub fn is_witness(&self) -> Result<bool> {
        match self {
            // UInt8 gadget does not implement ToBytesGadget which is needed
            // by IsWitness implementors but [UInt8] does so we are making a
            // special case for it.
            SimpleUInt8(v) => [v.clone()].is_witness(),
            SimpleInt8(v) => v.is_witness(),
            SimpleUInt16(v) => v.is_witness(),
            SimpleUInt32(v) => v.is_witness(),
            SimpleUInt64(v) => v.is_witness(),
            SimpleRecord(_) => Ok(true),
            SimpleAddress(v) => v.is_witness(),
            SimpleBoolean(v) => v.is_witness(),
            SimpleField(v) => v.is_witness(),
        }
    }

    pub fn is_constant(&self) -> bool {
        match self {
            // UInt8 gadget does not implement ToBytesGadget which is needed
            // by IsWitness implementors but [UInt8] does so we are making a
            // special case for it.
            SimpleUInt8(v) => [v.clone()].is_constant(),
            SimpleInt8(v) => v.is_constant(),
            SimpleUInt16(v) => v.is_constant(),
            SimpleUInt32(v) => v.is_constant(),
            SimpleUInt64(v) => v.is_constant(),
            SimpleRecord(_) => true,
            SimpleAddress(v) => v.is_constant(),
            SimpleBoolean(v) => v.is_constant(),
            SimpleField(v) => v.is_constant(),
        }
    }
}
