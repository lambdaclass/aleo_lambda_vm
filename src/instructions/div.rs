use crate::{
    circuit_io_type::CircuitIOType, instructions::helpers, UInt16Gadget, UInt32Gadget, UInt64Gadget,
};
use anyhow::{bail, ensure, Result};
use ark_r1cs_std::{prelude::AllocVar, select::CondSelectGadget, R1CSVar, ToBitsGadget};
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{traits::BitwiseOperationGadget, UInt8Gadget},
    marlin::ConstraintSystemRef,
};
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn div(
    operands: &IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(dividend), SimpleUInt8(divisor)] => {
            ensure!(divisor.value()? != 0_u8, "attempt to divide by zero");
            let mut quotient = UInt8Gadget::new_witness(constraint_system.clone(), || Ok(0))?;
            for (i, divisor_bit) in divisor.to_bits_le()?.iter().enumerate() {
                // If the divisor bit is a 1.
                let addend = UInt8Gadget::shift_right(dividend, i, constraint_system.clone())?;
                let mut partial_sum = helpers::add(&quotient.to_bits_be()?, &addend.to_bits_be()?)?;
                partial_sum.reverse();
                quotient = UInt8Gadget::conditionally_select(
                    divisor_bit,
                    &UInt8Gadget::from_bits_le(&partial_sum),
                    &quotient,
                )?;
            }
            Ok(SimpleUInt8(quotient))
        }
        [SimpleUInt16(dividend), SimpleUInt16(divisor)] => {
            ensure!(divisor.value()? != 0_u16, "attempt to divide by zero");
            let mut quotient = UInt16Gadget::new_witness(constraint_system.clone(), || Ok(0))?;
            for (i, divisor_bit) in divisor.to_bits_le().iter().enumerate() {
                // If the divisor bit is a 1.
                let addend = UInt16Gadget::shift_right(dividend, i, constraint_system.clone())?;
                quotient = UInt16Gadget::conditionally_select(
                    divisor_bit,
                    &UInt16Gadget::addmany(&[quotient.clone(), addend])?,
                    &quotient,
                )?;
            }
            Ok(SimpleUInt16(quotient))
        }
        [SimpleUInt32(dividend), SimpleUInt32(divisor)] => {
            ensure!(divisor.value()? != 0_u32, "attempt to divide by zero");
            let mut quotient = UInt32Gadget::new_witness(constraint_system.clone(), || Ok(0))?;
            for (i, divisor_bit) in divisor.to_bits_le().iter().enumerate() {
                // If the divisor bit is a 1.
                let addend = UInt32Gadget::shift_right(dividend, i, constraint_system.clone())?;
                quotient = UInt32Gadget::conditionally_select(
                    divisor_bit,
                    &UInt32Gadget::addmany(&[quotient.clone(), addend])?,
                    &quotient,
                )?;
            }
            Ok(SimpleUInt32(quotient))
        }
        [SimpleUInt64(dividend), SimpleUInt64(divisor)] => {
            ensure!(divisor.value()? != 0_u64, "attempt to divide by zero");
            let mut quotient = UInt64Gadget::new_witness(constraint_system.clone(), || Ok(0))?;
            for (i, divisor_bit) in divisor.to_bits_le().iter().enumerate() {
                // If the divisor bit is a 1.
                let addend = UInt64Gadget::shift_right(dividend, i, constraint_system.clone())?;
                quotient = UInt64Gadget::conditionally_select(
                    divisor_bit,
                    &UInt64Gadget::addmany(&[quotient.clone(), addend])?,
                    &quotient,
                )?;
            }
            Ok(SimpleUInt64(quotient))
        }
        [_, _] => bail!("div is not supported for the given types"),
        [..] => bail!("div requires two operands"),
    }
}

#[cfg(test)]
mod div_unit_tests {
    use crate::{
        instructions::div::div,
        CircuitIOType::{
            self, SimpleAddress, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
        },
        UInt16Gadget, UInt32Gadget, UInt64Gadget,
    };
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{AddressGadget, ConstraintF, UInt8Gadget};

    fn address(n: u64) -> (String, [u8; 63]) {
        let mut address_bytes = [0_u8; 63];
        let address_string =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_string, address_bytes)
    }

    fn sample_operands(
        dividend: CircuitIOType,
        divisor: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), dividend);
        operands.insert("r1".to_owned(), divisor);
        operands
    }

    #[test]
    fn test_u8_dividing_by_zero_should_raise_an_error() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = u8::MAX;
        let primitive_divisor = 0_u8;

        let dividend =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());

        let result = div(&sample_operands(dividend, divisor), cs).unwrap_err();

        assert_eq!(result.to_string(), "attempt to divide by zero");
    }

    #[test]
    fn test_u8_dividing_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0_u8;
        let primitive_divisor = u8::MAX;

        let dividend =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u8_dividing_by_one_should_result_on_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0x55;
        let primitive_divisor = 1_u8;

        let dividend =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u8_if_the_dividend_is_one_the_result_should_be_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 1_u8;
        let primitive_divisor = 0x55;

        let dividend =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_dividing_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0_u16;
        let primitive_divisor = u16::MAX;

        let dividend =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_dividing_by_zero_should_raise_an_error() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = u16::MAX;
        let primitive_divisor = 0_u16;

        let dividend =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());

        let result = div(&sample_operands(dividend, divisor), cs).unwrap_err();

        assert_eq!(result.to_string(), "attempt to divide by zero");
    }

    #[test]
    fn test_u16_dividing_by_one_should_result_on_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0x5555;
        let primitive_divisor = 1_u16;

        let dividend =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_if_the_dividend_is_one_the_result_should_be_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 1_u16;
        let primitive_divisor = 0x5555;

        let dividend =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_dividing_by_zero_should_raise_an_error() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = u32::MAX;
        let primitive_divisor = 0_u32;

        let dividend =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());

        let result = div(&sample_operands(dividend, divisor), cs).unwrap_err();

        assert_eq!(result.to_string(), "attempt to divide by zero");
    }

    #[test]
    fn test_u32_dividing_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0_u32;
        let primitive_divisor = u32::MAX;

        let dividend =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_dividing_by_one_should_result_on_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0x55555555;
        let primitive_divisor = 1_u32;

        let dividend =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_if_the_dividend_is_one_the_result_should_be_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 1_u32;
        let primitive_divisor = 0x55555555;

        let dividend =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_dividing_by_zero_should_raise_an_error() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = u64::MAX;
        let primitive_divisor = 0_u64;

        let dividend =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());

        let result = div(&sample_operands(dividend, divisor), cs).unwrap_err();

        assert_eq!(result.to_string(), "attempt to divide by zero");
    }

    #[test]
    fn test_u64_dividing_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0_u64;
        let primitive_divisor = u64::MAX;

        let dividend =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_dividing_by_one_should_result_on_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 0x5555555555555555;
        let primitive_divisor = 1_u64;

        let dividend =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_if_the_dividend_is_one_the_result_should_be_the_dividend() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_dividend = 1_u64;
        let primitive_divisor = 0x5555555555555555;

        let dividend =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_dividend)).unwrap());
        let divisor =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_divisor)).unwrap());
        let expected_product = dividend.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            div(&sample_operands(dividend, divisor), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_div_with_more_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;
        let primitive_third_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let third_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_third_operand)).unwrap(),
        );

        let mut operands = sample_operands(left_operand, right_operand);
        operands.insert("r2".to_owned(), third_operand);

        let result = div(&operands, cs).unwrap_err();

        assert_eq!(result.to_string(), "div requires two operands");
    }

    #[test]
    fn test_div_with_less_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let mut operands = sample_operands(left_operand, right_operand);
        operands.remove("r1");

        let result = div(&operands, cs).unwrap_err();

        assert_eq!(result.to_string(), "div requires two operands");
    }

    #[test]
    fn test_div_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let result = div(&sample_operands(left_operand, right_operand), cs).unwrap_err();

        assert_eq!(
            result.to_string(),
            "div is not supported for the given types"
        );
    }
}
