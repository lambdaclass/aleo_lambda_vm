use anyhow::{bail, Result};
use ark_r1cs_std::R1CSVar;

pub use CircuitIOType::{SimpleUInt128, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

#[derive(Clone)]
pub enum CircuitIOType {
    SimpleUInt8(crate::UInt8Gadget),
    SimpleUInt16(crate::UInt16Gadget),
    SimpleUInt32(crate::UInt32Gadget),
    SimpleUInt64(crate::UInt64Gadget),
    SimpleUInt128(crate::UInt128Gadget),
}

impl CircuitIOType {
    // Aleo instructions support the addition of two numbers and not for UInt8.
    pub fn addmany(operands: &[CircuitIOType]) -> Result<CircuitIOType> {
        match operands {
            // [SimpleUInt8(addend), SimpleUInt8(augend)] => Ok(SimpleUInt8(UInt8::<ConstraintF>::addmany(&[addend.clone(), augend.clone()])?)),
            [SimpleUInt16(addend), SimpleUInt16(augend)] => {
                Ok(SimpleUInt16(crate::UInt16Gadget::addmany(&[
                    addend.clone(),
                    augend.clone(),
                ])?))
            }
            [SimpleUInt32(addend), SimpleUInt32(augend)] => {
                Ok(SimpleUInt32(crate::UInt32Gadget::addmany(&[
                    addend.clone(),
                    augend.clone(),
                ])?))
            }
            [SimpleUInt64(addend), SimpleUInt64(augend)] => {
                Ok(SimpleUInt64(crate::UInt64Gadget::addmany(&[
                    addend.clone(),
                    augend.clone(),
                ])?))
            }
            [SimpleUInt128(_addend), SimpleUInt128(_augend)] => {
                unimplemented!("TODO: Figure out if we want to support U128 operations")
            }
            [..] => bail!("Unsupported operand types for addmany"),
        }
    }

    // TODO: This is temporary, we need to find a better way to handle this method.
    pub fn value(&self) -> Result<String> {
        match self {
            SimpleUInt8(value) => Ok(value.value()?.to_string()),
            SimpleUInt16(value) => Ok(value.value()?.to_string()),
            SimpleUInt32(value) => Ok(value.value()?.to_string()),
            SimpleUInt64(value) => Ok(value.value()?.to_string()),
            SimpleUInt128(value) => Ok(value.value()?.to_string()),
        }
    }
}
