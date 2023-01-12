use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use ark_r1cs_std::R1CSVar;
use indexmap::IndexMap;
use simpleworks::{gadgets::traits::BitShiftGadget, marlin::ConstraintSystemRef};
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn shl(
    operands: &IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        // UInt8 Magnitude.
        [SimpleUInt8(value_to_shift), SimpleUInt8(positions)] => Ok(SimpleUInt8(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt16(value_to_shift), SimpleUInt8(positions)] => Ok(SimpleUInt16(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt32(value_to_shift), SimpleUInt8(positions)] => Ok(SimpleUInt32(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt64(value_to_shift), SimpleUInt8(positions)] => Ok(SimpleUInt64(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        // UInt16 Magnitude.
        [SimpleUInt8(value_to_shift), SimpleUInt16(positions)] => Ok(SimpleUInt8(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt16(value_to_shift), SimpleUInt16(positions)] => Ok(SimpleUInt16(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt32(value_to_shift), SimpleUInt16(positions)] => Ok(SimpleUInt32(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt64(value_to_shift), SimpleUInt16(positions)] => Ok(SimpleUInt64(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        // UInt32 Magnitude.
        [SimpleUInt8(value_to_shift), SimpleUInt32(positions)] => Ok(SimpleUInt8(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt16(value_to_shift), SimpleUInt32(positions)] => Ok(SimpleUInt16(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt32(value_to_shift), SimpleUInt32(positions)] => Ok(SimpleUInt32(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [SimpleUInt64(value_to_shift), SimpleUInt32(positions)] => Ok(SimpleUInt64(
            value_to_shift.shift_left(positions.value()?.try_into()?, constraint_system)?,
        )),
        [_] => bail!("shr is not supported for the given type"),
        [..] => bail!("shr requires one operand"),
    }
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    };

    use crate::{instructions::shr, CircuitIOType};

    fn sample_shift_operands(
        number_to_shift: CircuitIOType,
        positions_to_shift: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), number_to_shift);
        operands.insert("r1".to_owned(), positions_to_shift);
        operands
    }

    #[test]
    fn test_u8_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_more_than_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_one_bit_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_all_bits_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u8::MAX;
        let primitive_positions_to_shift = 8;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_more_than_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_one_bit_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_all_bits_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u16::MAX;
        let primitive_positions_to_shift = 16;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_more_than_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_one_bit_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_all_bits_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u32::MAX;
        let primitive_positions_to_shift = 32;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_more_than_one_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_one_bit_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_all_bits_left_shift_u8_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u64::MAX;
        let primitive_positions_to_shift = 64;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_more_than_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_one_bit_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_all_bits_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u8::MAX;
        let primitive_positions_to_shift = 8;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_more_than_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_one_bit_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_all_bits_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u16::MAX;
        let primitive_positions_to_shift = 16;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_more_than_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_one_bit_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_all_bits_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u32::MAX;
        let primitive_positions_to_shift = 32;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_more_than_one_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_one_bit_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_all_bits_left_shift_u16_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u64::MAX;
        let primitive_positions_to_shift = 64;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_more_than_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_one_bit_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u8_overflow_all_bits_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u8::MAX;
        let primitive_positions_to_shift = 8;

        let value_to_shift = CircuitIOType::SimpleUInt8(
            UInt8Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_more_than_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_one_bit_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u16_overflow_all_bits_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u16::MAX;
        let primitive_positions_to_shift = 16;

        let value_to_shift = CircuitIOType::SimpleUInt16(
            UInt16Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_more_than_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_one_bit_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u32_overflow_all_bits_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u32::MAX;
        let primitive_positions_to_shift = 32;

        let value_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 2;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_more_than_one_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 4;
        let primitive_positions_to_shift = 2;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = primitive_value_to_shift >> primitive_positions_to_shift;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_one_bit_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = 1;
        let primitive_positions_to_shift = 1;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }

    #[test]
    fn test_u64_overflow_all_bits_left_shift_u32_positions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_value_to_shift = u64::MAX;
        let primitive_positions_to_shift = 64;

        let value_to_shift = CircuitIOType::SimpleUInt64(
            UInt64Gadget::new_witness(constraint_system.clone(), || Ok(primitive_value_to_shift))
                .unwrap(),
        );
        let positions_to_shift = CircuitIOType::SimpleUInt32(
            UInt32Gadget::new_witness(constraint_system.clone(), || {
                Ok(primitive_positions_to_shift)
            })
            .unwrap(),
        );

        let expected_byte = 0_i32;

        let result = shr(
            &sample_shift_operands(value_to_shift, positions_to_shift),
            constraint_system.clone(),
        )
        .unwrap();

        assert!(constraint_system.is_satisfied().unwrap());
        assert_eq!(expected_byte.to_string(), result.value().unwrap());
    }
}
