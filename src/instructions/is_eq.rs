use crate::circuit_io_type::CircuitIOType::{self, SimpleAddress, SimpleRecord};

use anyhow::{anyhow, bail, Result};

use ark_r1cs_std::prelude::EqGadget;
use indexmap::IndexMap;
use snarkvm::prelude::{Literal, Operand, Register, Testnet3};
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn is_eq(
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
    _is_eq(&instruction_operands)
}

// Aleo instructions support the addition of two numbers and not for UInt8.
pub fn _is_eq(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [_, _] => bail!("is.eq is not supported for the given types"),
        [..] => bail!("is.eq requires two operands"),
    }
}

#[cfg(test)]
mod is_eq_tests {
    use crate::CircuitIOType::{
        SimpleAddress, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    };

    use crate::{instructions::is_eq::_is_eq, CircuitIOType};

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
        left_operand: CircuitIOType,
        right_operand: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), left_operand);
        operands.insert("r1".to_owned(), right_operand);
        operands
    }

    #[test]
    fn test_u8_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u8_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_is_eq_with_more_than_two_operands() {
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

        let result = _is_eq(&operands).unwrap_err();

        assert_eq!(result.to_string(), "is.eq requires two operands");
    }

    #[test]
    fn test_is_eq_with_less_than_two_operands() {
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

        let result = _is_eq(&operands).unwrap_err();

        assert_eq!(result.to_string(), "is.eq requires two operands");
    }

    #[test]
    fn test_is_eq_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let result = _is_eq(&sample_operands(left_operand, right_operand)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "is.eq is not supported for the given types"
        );
    }
}
