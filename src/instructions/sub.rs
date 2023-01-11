use crate::{
    circuit_io_type::CircuitIOType, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget,
};
use anyhow::{bail, ensure, Result};
use ark_r1cs_std::{prelude::Boolean, R1CSVar};
use indexmap::IndexMap;
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

// Aleo instructions support the subtraction of two numbers and not for UInt8.
// We compute the subtraction as an addition thanks to the following:
// minuend - subtrahend = difference
// minuend + module - subtrahend - module = difference
// module - (minuend + module - subtrahend) = difference
// not(minuend + not(subtrahend)) = difference
// where module = 2^size and module - n could be done negating bit by bit in binary so there are no subtractions.
pub fn sub(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt16(minuend), SimpleUInt16(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt16Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt16Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt16Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt16Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt16(difference))
        }
        [SimpleUInt32(minuend), SimpleUInt32(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt32Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt32Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt32Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt32Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt32(difference))
        }
        [SimpleUInt64(minuend), SimpleUInt64(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt64Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt64Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt64Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt64Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt64(difference))
        }
        [_, _] => bail!("Subtraction is not supported for the given types"),
        [..] => bail!("Subtraction requires two operands"),
    }
}

fn negate(bits: Vec<Boolean<ConstraintF>>) -> Vec<Boolean<ConstraintF>> {
    bits.into_iter()
        .map(|bit| bit.not())
        .collect::<Vec<Boolean<ConstraintF>>>()
}

#[cfg(test)]
mod subtract_tests {
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use indexmap::IndexMap;

    use crate::{
        CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64},
        ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget,
    };

    #[test]
    fn test_u16_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u16;
        let primitive_subtrahend = 1_u16;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u16_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u16;
        let primitive_subtrahend = 1_u16;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u16_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u16;
        let primitive_subtrahend = 2_u16;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }

    #[test]
    fn test_u32_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u32;
        let primitive_subtrahend = 1_u32;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u32_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u32;
        let primitive_subtrahend = 1_u32;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u32_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u32;
        let primitive_subtrahend = 2_u32;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }

    #[test]
    fn test_u64_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u64;
        let primitive_subtrahend = 1_u64;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u64_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u64;
        let primitive_subtrahend = 1_u64;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u64_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u64;
        let primitive_subtrahend = 2_u64;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }
}
