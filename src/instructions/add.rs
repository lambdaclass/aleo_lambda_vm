use crate::{circuit_io_type::CircuitIOType, UInt16Gadget, UInt32Gadget, UInt64Gadget};

use anyhow::{bail, Result};

pub use CircuitIOType::{SimpleUInt128, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

// Aleo instructions support the addition of two numbers and not for UInt8.
pub fn add(operands: &[CircuitIOType]) -> Result<CircuitIOType> {
    match operands {
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
        [SimpleUInt128(_addend), SimpleUInt128(_augend)] => {
            unimplemented!("TODO: Figure out if we want to support U128 operations")
        }
        [..] => bail!("Unsupported operand types for addmany"),
    }
}
