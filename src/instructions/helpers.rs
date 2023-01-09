use std::{iter::Peekable, slice::Chunks, vec::IntoIter};

use anyhow::{anyhow, bail, ensure, Result};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    R1CSVar,
};
use simpleworks::{gadgets::ConstraintF, marlin::ConstraintSystemRef};

pub fn to_bits_be(bits: &[Boolean<ConstraintF>]) -> Result<Vec<Boolean<ConstraintF>>> {
    let mut bits_be = bits.to_vec();
    bits_be.reverse();
    Ok(bits_be)
}

pub fn add(
    augend: &[Boolean<ConstraintF>],
    addend: &Vec<Boolean<ConstraintF>>,
) -> Result<Vec<Boolean<ConstraintF>>> {
    let mut sum = vec![Boolean::<ConstraintF>::FALSE; augend.len()];
    let mut carry = Boolean::<ConstraintF>::FALSE;
    for (i, (augend_bit, addend_bit)) in augend.iter().zip(addend).enumerate().rev() {
        // Bit by bit sum is an xor for the augend, the addend and the carry bits.
        // carry in | addend | augend | carry out | augend + addend |
        //     0    |    0   |   0    |     0     |        0        |
        //     0    |    0   |   1    |     0     |        1        |
        //     0    |    1   |   0    |     0     |        1        |
        //     0    |    1   |   1    |     1     |        0        |
        //     1    |    0   |   0    |     0     |        1        |
        //     1    |    0   |   1    |     1     |        0        |
        //     1    |    1   |   0    |     1     |        0        |
        //     1    |    1   |   1    |     1     |        1        |
        // sum[i] = (!carry & (augend_bit ^ addend_bit)) | (carry & !(augend_bit ^ addend_bit))
        //        = augend_bit ^ addend_bit ^ carry
        *sum.get_mut(i)
            .ok_or_else(|| anyhow!("Error accessing the index of sum"))? =
            carry.xor(augend_bit)?.xor(addend_bit)?;
        // To simplify things, the variable carry acts for both the carry in and
        // the carry out.
        // The carry out is augend & addend when the carry in is 0, and it is
        // augend | addend when the carry in is 1.
        // carry = carry.not()
        carry = (carry.not().and(&(augend_bit.and(addend_bit)?))?)
            .or(&(carry.and(&(augend_bit.or(addend_bit)?))?))?;
    }
    Ok(sum.to_vec())
}

pub fn encode_next_pair(
    encoded_bit_pairs: &mut Vec<String>,
    encoded_bits: &mut Peekable<Chunks<'_, String>>,
) -> Vec<String> {
    if let Some([a, b]) = encoded_bits.next() {
        match (a.as_str(), b.as_str()) {
            ("0", "0") => {
                encoded_bit_pairs.push("0".to_owned());
                encode_next_pair(encoded_bit_pairs, encoded_bits);
            }
            ("0", "+1") | ("+1", "-1") => {
                encoded_bit_pairs.push("+1".to_owned());
                encode_next_pair(encoded_bit_pairs, encoded_bits);
            }
            ("0", "-1") | ("-1", "+1") => {
                encoded_bit_pairs.push("-1".to_owned());
                encode_next_pair(encoded_bit_pairs, encoded_bits);
            }
            ("+1", "0") => {
                encoded_bit_pairs.push("+2".to_owned());
                encode_next_pair(encoded_bit_pairs, encoded_bits);
            }
            ("-1", "0") => {
                encoded_bit_pairs.push("-2".to_owned());
                encode_next_pair(encoded_bit_pairs, encoded_bits);
            }
            _ => unreachable!(),
        }
    }

    encoded_bit_pairs.clone()
}

pub fn encode_bits_pairwise(bits: &[Boolean<ConstraintF>]) -> Result<Vec<String>> {
    Ok(encode_next_pair(
        &mut Vec::new(),
        &mut encode_bits(bits)?.chunks(2).peekable(),
    ))
}

pub fn peek_bit(
    bits: &mut Peekable<IntoIter<Boolean<ConstraintF>>>,
) -> Option<&Boolean<ConstraintF>> {
    bits.peek()
}

pub fn peek_bit_is_one(bits: &mut Peekable<IntoIter<Boolean<ConstraintF>>>) -> Result<bool> {
    if let Some(peek) = peek_bit(bits) {
        Ok(peek.value()?)
    } else {
        Ok(false)
    }
}

pub fn encode_next_bit(
    encoded_bits: &mut Vec<String>,
    bits: &mut Peekable<IntoIter<Boolean<ConstraintF>>>,
) -> Result<Vec<String>> {
    match bits.next() {
        Some(boolean) => {
            if boolean.value()? {
                // It's another 1 in the 1's sequence.
                if peek_bit_is_one(bits)? {
                    encoded_bits.push("0".to_owned());
                    encode_next_bit(encoded_bits, bits)
                // It's the start of the 1's sequence.
                } else {
                    encoded_bits.push("-1".to_owned());
                    encode_next_bit(encoded_bits, bits)
                }
            } else {
                // It's the end of the 1's sequence.
                if peek_bit_is_one(bits)? {
                    encoded_bits.push("+1".to_owned());
                    encode_next_bit(encoded_bits, bits)
                // It's another 0 in the 0's sequence.
                } else {
                    encoded_bits.push("0".to_owned());
                    encode_next_bit(encoded_bits, bits)
                }
            }
        }
        None => Ok(encoded_bits.clone()),
    }
}

pub fn encode_bits(bits: &[Boolean<ConstraintF>]) -> Result<Vec<String>> {
    encode_next_bit(
        &mut Vec::new(),
        // Allowed because the suggestion is to use .iter().clone() instead of
        // .to_vec() but Boolean does not implement the Cloned trait.
        #[allow(clippy::unnecessary_to_owned)]
        &mut bits.to_vec().into_iter().peekable(),
    )
}

// C(n) = M - n where M = 2^b with b the amount of bits. Because may not have
// enough bits to represent M we subtract 1 to it and add 1 to maintain equality.
// Finally C(n) = (M-1) - n + 1 which in an 4-bit example we have:
// C(0010) = (10000 - 1) - 0010 + 0001
//         = 1111 - 0010 + 0001
//         = 1110.
// In binary the same result could be achieved by negating bit by bit and adding 1.
pub fn twos_complement(
    primitive_bits: &Vec<Boolean<ConstraintF>>,
) -> Result<Vec<Boolean<ConstraintF>>> {
    let mut twos_complement_bits = vec![Boolean::<ConstraintF>::FALSE; primitive_bits.len()];
    let mut carry = Boolean::TRUE;
    for (twos_complement_bit, primitive_bit) in
        twos_complement_bits.iter_mut().zip(primitive_bits).rev()
    {
        *twos_complement_bit = primitive_bit.not().xor(&carry)?;
        carry = carry.and(&twos_complement_bit.not())?;
    }
    Ok(twos_complement_bits.to_vec())
}

// TODO: generate constraints. Left bit shifting
pub fn shift_left(
    bits_to_shift: &Vec<Boolean<ConstraintF>>,
    n_bits_to_shift: usize,
    constraint_system: ConstraintSystemRef,
) -> Result<Vec<Boolean<ConstraintF>>> {
    if n_bits_to_shift == 0 {
        return Ok(bits_to_shift.to_vec());
    }
    let mut shifted = Vec::new();
    for multiplicand_bit in bits_to_shift.iter().skip(n_bits_to_shift) {
        shifted.push((*multiplicand_bit).clone())
    }

    for _ in 0..n_bits_to_shift {
        if bits_to_shift.is_constant() {
            shifted.push(Boolean::<ConstraintF>::new_input(
                constraint_system.clone(),
                || Ok(false),
            )?)
        } else {
            shifted.push(Boolean::<ConstraintF>::new_witness(
                constraint_system.clone(),
                || Ok(false),
            )?)
        }
    }
    ensure!(shifted.len() == bits_to_shift.len());
    Ok(shifted)
}

// TODO: generate constraints. Right bit shifting
pub fn shift_right(
    bits_to_shift: &Vec<Boolean<ConstraintF>>,
    n_bits_to_shift: usize,
    constraint_system: ConstraintSystemRef,
) -> Result<Vec<Boolean<ConstraintF>>> {
    if n_bits_to_shift == 0 {
        return Ok(bits_to_shift.to_vec());
    }
    let mut shifted = Vec::new();

    for _ in 0..n_bits_to_shift {
        if bits_to_shift.is_constant() {
            shifted.push(Boolean::<ConstraintF>::new_input(
                constraint_system.clone(),
                || Ok(false),
            )?)
        } else {
            shifted.push(Boolean::<ConstraintF>::new_witness(
                constraint_system.clone(),
                || Ok(false),
            )?)
        }
    }
    for multiplicand_bit in bits_to_shift
        .iter()
        .take(bits_to_shift.len() - n_bits_to_shift)
    {
        shifted.push((*multiplicand_bit).clone())
    }

    ensure!(shifted.len() == bits_to_shift.len());
    Ok(shifted)
}

pub fn modified_booth_mul(
    multiplicand: &Vec<Boolean<ConstraintF>>,
    multiplier: &[Boolean<ConstraintF>],
    constraint_system: ConstraintSystemRef,
) -> Result<Vec<Boolean<ConstraintF>>> {
    let mut product = vec![Boolean::FALSE; multiplicand.len()];
    let encoded_multiplier = encode_bits_pairwise(multiplier)?;
    for (i, token) in encoded_multiplier.iter().rev().enumerate() {
        let partial_product = match token.as_str() {
            "0" => continue,
            "+1" => shift_left(multiplicand, 2 * i, constraint_system.clone())?,
            "-1" => {
                let multiplicand_twos_complement = twos_complement(multiplicand)?;
                shift_left(
                    &multiplicand_twos_complement,
                    2 * i,
                    constraint_system.clone(),
                )?
            }
            "+2" => shift_left(multiplicand, 2 * i + 1, constraint_system.clone())?,
            "-2" => {
                let multiplicand_twos_complement = twos_complement(multiplicand)?;
                shift_left(
                    &multiplicand_twos_complement,
                    2 * i + 1,
                    constraint_system.clone(),
                )?
            }
            _ => bail!("Invalid encoded token"),
        };
        product = add(&product, &partial_product)?;
    }
    Ok(product)
}

#[cfg(test)]
mod tests {
    use crate::instructions::helpers::{
        add, encode_bits, encode_bits_pairwise, shift_right, twos_complement,
    };
    use ark_r1cs_std::{
        prelude::{AllocVar, Boolean},
        R1CSVar, ToBitsGadget,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use simpleworks::gadgets::{ConstraintF, UInt8Gadget};

    use super::shift_left;

    const U8_BITS: usize = 8;
    const U8_ONE: [Boolean<ConstraintF>; 8] = [
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::TRUE,
    ];
    const U8_THREE: [Boolean<ConstraintF>; 8] = [
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
    ];
    const U8_FOUR: [Boolean<ConstraintF>; 8] = [
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
    ];
    const U8_SEVEN: [Boolean<ConstraintF>; 8] = [
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::FALSE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
    ];
    const U8_MAX: [Boolean<ConstraintF>; 8] = [
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
        Boolean::<ConstraintF>::TRUE,
    ];

    /* First Encoding */

    #[test]
    fn test_u8_all_zeros() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_encoded_bits = vec!["0", "0", "0", "0", "0", "0", "0", "0"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_all_ones() {
        let bits = U8_MAX.to_vec();
        let expected_encoded_bits = vec!["0", "0", "0", "0", "0", "0", "0", "-1"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_only_one_one() {
        let bits = U8_ONE.to_vec();
        let expected_encoded_bits = vec!["0", "0", "0", "0", "0", "0", "+1", "-1"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_consecutive_ones() {
        let bits = U8_SEVEN.to_vec();
        let expected_encoded_bits = vec!["0", "0", "0", "0", "+1", "0", "0", "-1"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_alternating_ones_and_zeros_starting_with_one() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let expected_encoded_bits = vec!["+1", "-1", "+1", "-1", "+1", "-1", "+1", "-1"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_alternating_ones_and_zeros_starting_with_zero() {
        let bits = vec![
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_encoded_bits = vec!["-1", "+1", "-1", "+1", "-1", "+1", "-1", "0"];

        assert_eq!(encode_bits(&bits).unwrap(), expected_encoded_bits);
    }

    /* Second Encoding */

    #[test]
    fn test_u8_all_zeros_pairwise_encoding() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_encoded_bits = vec!["0", "0", "0", "0"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_all_ones_pairwise_encoding() {
        let bits = U8_MAX.to_vec();
        let expected_encoded_bits = vec!["0", "0", "0", "-1"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_only_one_one_pairwise_encoding() {
        let bits = U8_ONE.to_vec();
        let expected_encoded_bits = vec!["0", "0", "0", "+1"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_consecutive_ones_pairwise_encoding() {
        let bits = U8_SEVEN.to_vec();
        let expected_encoded_bits = vec!["0", "0", "+2", "-1"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_alternating_ones_and_zeros_starting_with_one_pairwise_encoding() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let expected_encoded_bits = vec!["+1", "+1", "+1", "+1"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    #[test]
    fn test_u8_alternating_ones_and_zeros_starting_with_zero_pairwise_encoding() {
        let bits = vec![
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_encoded_bits = vec!["-1", "-1", "-1", "-2"];

        assert_eq!(encode_bits_pairwise(&bits).unwrap(), expected_encoded_bits);
    }

    /* Two's Complement */

    #[test]
    fn test_u8_twos_complement_without_carry() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let expected_twos_complement_bits = vec![
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
        ];

        assert_eq!(
            twos_complement(&bits).unwrap().value().unwrap(),
            expected_twos_complement_bits.value().unwrap()
        );
    }

    #[test]
    fn test_u8_twos_complement_with_one_carry() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_twos_complement_bits = vec![
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            twos_complement(&bits).unwrap().value().unwrap(),
            expected_twos_complement_bits.value().unwrap()
        );
    }

    #[test]
    fn test_u8_twos_complement_with_more_than_one_carry() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_twos_complement_bits = vec![
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            twos_complement(&bits).unwrap().value().unwrap(),
            expected_twos_complement_bits.value().unwrap()
        );
    }

    #[test]
    fn test_u8_twos_complement_with_overflow() {
        let bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];
        let expected_twos_complement_bits = bits.clone();

        assert_eq!(
            twos_complement(&bits).unwrap().value().unwrap(),
            expected_twos_complement_bits.value().unwrap()
        );
    }

    /* u8 addition */

    #[test]
    fn test_u8_add_without_carry() {
        let augend = vec![Boolean::<ConstraintF>::FALSE; U8_BITS];
        let addend = vec![Boolean::<ConstraintF>::TRUE; U8_BITS];

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            addend.value().unwrap()
        );
    }

    #[test]
    fn test_u8_add_with_one_carry() {
        let augend = U8_ONE.to_vec();
        let addend = augend.clone();
        let expected_result = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            expected_result.value().unwrap()
        );
    }

    #[test]
    fn test_u8_add_with_more_than_one_carry() {
        let augend = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let addend = U8_ONE.to_vec();
        let expected_result = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            expected_result.value().unwrap()
        );
    }

    #[test]
    fn test_u8_add_with_overflow() {
        let augend = vec![Boolean::<ConstraintF>::TRUE; U8_BITS];
        let addend = U8_ONE.to_vec();
        let expected_result = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            expected_result.value().unwrap()
        );
    }

    #[test]
    fn test_u8_add() {
        let augend = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let addend = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
        ];
        let expected_result = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ];

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            expected_result.value().unwrap()
        );
    }

    #[test]
    fn test_addition_is_commutative() {
        let augend = U8_THREE.to_vec();
        let addend = U8_FOUR.to_vec();

        assert_eq!(
            add(&augend, &addend).unwrap().value().unwrap(),
            add(&addend, &augend).unwrap().value().unwrap()
        );
    }

    #[test]
    fn test_shift_left_zero_times_leave_the_bits_as_they_are() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(1))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();

        let left_shifted_bits = shift_left(&bits, 0, cs.clone())
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(left_shifted_bits, expected_shifted_bits);
    }

    #[test]
    fn test_shift_left_one_time() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(1))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ]
        .iter()
        .map(|b| b.value().unwrap())
        .collect::<Vec<_>>();

        let left_shifted_bits = shift_left(&bits, 1, cs.clone())
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(left_shifted_bits, expected_shifted_bits);
    }

    #[test]
    fn test_shift_left_more_than_one_time() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(1))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = U8_FOUR
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        let left_shifted_bits = shift_left(&bits, 2, cs)
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(left_shifted_bits, expected_shifted_bits);
    }

    #[test]
    fn test_shift_right_one_time() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(4))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = vec![
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::FALSE,
            Boolean::<ConstraintF>::TRUE,
            Boolean::<ConstraintF>::FALSE,
        ]
        .iter()
        .map(|b| b.value().unwrap())
        .collect::<Vec<_>>();

        let right_shifted_bits = shift_right(&bits, 1, cs.clone())
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(right_shifted_bits, expected_shifted_bits);
    }

    #[test]
    fn test_shift_right_more_than_one_time() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(4))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = U8_ONE
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        let right_shifted_bits = shift_right(&bits, 2, cs.clone())
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(right_shifted_bits, expected_shifted_bits);
    }

    #[test]
    fn test_shift_right_zero_times_leave_the_bits_as_they_are() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let bits = UInt8Gadget::new_witness(cs.clone(), || Ok(1))
            .unwrap()
            .to_bits_be()
            .unwrap();
        let expected_shifted_bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();

        let right_shifted_bits = shift_right(&bits, 0, cs.clone())
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(right_shifted_bits, expected_shifted_bits);
    }
}
