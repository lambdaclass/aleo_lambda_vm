use super::helpers::{add, shift_right, to_bits_be};
use crate::{
    circuit_io_type::CircuitIOType::{self, SimpleAddress, SimpleRecord},
    UInt16Gadget, UInt32Gadget, UInt64Gadget,
};
use anyhow::{anyhow, bail, ensure, Result};
use ark_r1cs_std::{prelude::AllocVar, R1CSVar, ToBitsGadget};
use indexmap::IndexMap;
use simpleworks::gadgets::UInt8Gadget;
use snarkvm::prelude::{Literal, Operand, Register, Testnet3};
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn div(
    operands: &[Operand<Testnet3>],
    program_variables: &mut IndexMap<String, Option<CircuitIOType>>,
) -> Result<CircuitIOType> {
    // instruction_operands is an IndexMap only to keep track of the
    // name of the record entries, so then when casting into records
    // we can know which entry is which.
    let mut instruction_operands: IndexMap<String, CircuitIOType> = IndexMap::new();
    for operand in operands {
        let variable_name = &operand.to_string();
        match (operand, program_variables.get(variable_name)) {
            (Operand::Register(Register::Member(locator, members)), Some(None)) => {
                if let Some(Some(SimpleRecord(record))) =
                    program_variables.get(&format!("r{locator}"))
                {
                    match members
                        .get(0)
                        .ok_or("Error getting the first member of a register member")
                        .map_err(|e| anyhow!("{}", e))?
                        .to_string()
                        .as_str()
                    {
                        "owner" => {
                            let owner_operand = SimpleAddress(record.owner.clone());
                            program_variables
                                .insert(variable_name.to_string(), Some(owner_operand.clone()));
                            instruction_operands.insert(variable_name.to_owned(), owner_operand);
                        }
                        "gates" => {
                            let gates_operand = SimpleUInt64(record.gates.clone());
                            program_variables
                                .insert(variable_name.to_string(), Some(gates_operand.clone()));
                            instruction_operands.insert(variable_name.to_owned(), gates_operand);
                        }
                        entry => {
                            let entry_operand = record
                                .entries
                                .get(entry)
                                .ok_or(format!("Could not find entry `{entry}` in record entries map. Record entries are {entries:?}", entries = record.entries.keys()))
                                .map_err(|e| anyhow!("{e}"))?
                                .clone();
                            program_variables
                                .insert(variable_name.to_string(), Some(entry_operand.clone()));
                            instruction_operands.insert(entry.to_owned(), entry_operand);
                        }
                    };
                }
            }
            (Operand::Register(_), Some(Some(operand))) => {
                instruction_operands.insert(variable_name.to_owned(), operand.clone());
            }
            (Operand::Register(r), Some(None)) => {
                bail!("Register \"{}\" not assigned in registers", r.to_string())
            }
            (Operand::Register(r), None) => {
                bail!("Register \"{}\" not found in registers", r.to_string())
            }
            (Operand::Literal(Literal::U64(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u64", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U64(v)), Some(None)) => bail!(
                "Literal \"{}\"u64 not assigned in registers",
                Operand::Literal(Literal::U64(*v))
            ),
            (Operand::Literal(_), _) => bail!("Literal operand not supported"),
            (Operand::ProgramID(_), _) => bail!("ProgramID operands are not supported"),
            (Operand::Caller, _) => bail!("Caller operands are not supported"),
        };
    }
    _div(&instruction_operands)
}

pub fn _div(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(dividend), SimpleUInt8(divisor)] => {
            ensure!(divisor.value()? != 0_u8, "attempt to divide by zero");
            let dividend_bits = dividend.to_bits_be()?;
            let cs = dividend.cs();
            let mut quotient = UInt8Gadget::new_witness(cs, || Ok(0))?.to_bits_be()?;
            for (i, divisor_bit) in divisor.to_bits_be()?.iter().rev().enumerate() {
                // If the divisor bit is a 1.
                if divisor_bit.value()? {
                    let addend = if i != 0 {
                        shift_right(&dividend_bits, i)?
                    } else {
                        dividend_bits.clone()
                    };
                    quotient = add(&quotient, &addend)?;
                }
            }
            // We reverse here because we were working with big endian.
            quotient.reverse();

            Ok(SimpleUInt8(UInt8Gadget::from_bits_le(&quotient)))
        }
        [SimpleUInt16(dividend), SimpleUInt16(divisor)] => {
            ensure!(divisor.value()? != 0_u16, "attempt to divide by zero");
            let dividend_bits = to_bits_be(&dividend.to_bits_le())?;
            let cs = dividend.cs();
            let mut quotient = UInt16Gadget::new_witness(cs, || Ok(0))?.to_bits_le();
            for (i, divisor_bit) in to_bits_be(&divisor.to_bits_le())?.iter().rev().enumerate() {
                // If the divisor bit is a 1.
                if divisor_bit.value()? {
                    let addend = if i != 0 {
                        shift_right(&dividend_bits, i)?
                    } else {
                        dividend_bits.clone()
                    };
                    quotient = add(&quotient, &addend)?;
                }
            }
            // We reverse here because we were working with big endian.
            quotient.reverse();

            Ok(SimpleUInt16(UInt16Gadget::from_bits_le(&quotient)))
        }
        [SimpleUInt32(dividend), SimpleUInt32(divisor)] => {
            ensure!(divisor.value()? != 0_u32, "attempt to divide by zero");
            let dividend_bits = to_bits_be(&dividend.to_bits_le())?;
            let cs = dividend.cs();
            let mut quotient = UInt32Gadget::new_witness(cs, || Ok(0))?.to_bits_le();
            for (i, divisor_bit) in to_bits_be(&divisor.to_bits_le())?.iter().rev().enumerate() {
                // If the divisor bit is a 1.
                if divisor_bit.value()? {
                    let addend = if i != 0 {
                        shift_right(&dividend_bits, i)?
                    } else {
                        dividend_bits.clone()
                    };
                    quotient = add(&quotient, &addend)?;
                }
            }
            // We reverse here because we were working with big endian.
            quotient.reverse();

            Ok(SimpleUInt32(UInt32Gadget::from_bits_le(&quotient)))
        }
        [SimpleUInt64(dividend), SimpleUInt64(divisor)] => {
            ensure!(divisor.value()? != 0_u64, "attempt to divide by zero");
            let dividend_bits = to_bits_be(&dividend.to_bits_le())?;
            let cs = dividend.cs();
            let mut quotient = UInt64Gadget::new_witness(cs, || Ok(0))?.to_bits_le();
            for (i, divisor_bit) in to_bits_be(&divisor.to_bits_le())?.iter().rev().enumerate() {
                // If the divisor bit is a 1.
                if divisor_bit.value()? {
                    let addend = if i != 0 {
                        shift_right(&dividend_bits, i)?
                    } else {
                        dividend_bits.clone()
                    };
                    quotient = add(&quotient, &addend)?;
                }
            }
            // We reverse here because we were working with big endian.
            quotient.reverse();

            Ok(SimpleUInt64(UInt64Gadget::from_bits_le(&quotient)))
        }
        [_, _] => bail!("div is not supported for the given types"),
        [..] => bail!("div requires two operands"),
    }
}

// TODO: Tests with overflow.
#[cfg(test)]
mod div_unit_tests {
    use crate::{
        instructions::div::_div,
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
        let divisor = SimpleUInt8(UInt8Gadget::new_witness(cs, || Ok(primitive_divisor)).unwrap());

        let result = _div(&sample_operands(dividend, divisor)).unwrap_err();

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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            SimpleUInt16(UInt16Gadget::new_witness(cs, || Ok(primitive_divisor)).unwrap());

        let result = _div(&sample_operands(dividend, divisor)).unwrap_err();

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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            SimpleUInt32(UInt32Gadget::new_witness(cs, || Ok(primitive_divisor)).unwrap());

        let result = _div(&sample_operands(dividend, divisor)).unwrap_err();

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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_divisor)).unwrap());

        let result = _div(&sample_operands(dividend, divisor)).unwrap_err();

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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
            _div(&sample_operands(dividend, divisor))
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
        let third_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_third_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.insert("r2".to_owned(), third_operand);

        let result = _div(&operands).unwrap_err();

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
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.remove("r1");

        let result = _div(&operands).unwrap_err();

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
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let result = _div(&sample_operands(left_operand, right_operand)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "div is not supported for the given types"
        );
    }
}
