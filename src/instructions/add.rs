use crate::{circuit_io_type::CircuitIOType, UInt16Gadget, UInt32Gadget, UInt64Gadget};

use anyhow::{bail, Result};

use indexmap::IndexMap;
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

// Aleo instructions support the addition of two numbers and not for UInt8.
pub fn add(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        // [SimpleUInt8(addend), SimpleUInt8(augend)] => Ok(SimpleUInt8(UInt8::<ConstraintF>::addmany(&[addend.clone(), augend.clone()])?)),
        [SimpleUInt16(addend), SimpleUInt16(augend)] => {
            Ok(SimpleUInt16(UInt16Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [SimpleUInt32(addend), SimpleUInt32(augend)] => {
            Ok(SimpleUInt32(UInt32Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [SimpleUInt64(addend), SimpleUInt64(augend)] => {
            Ok(SimpleUInt64(UInt64Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [..] => bail!("Unsupported operand types for addmany"),
    }
}
