use anyhow::{anyhow, Result};
use ark_r1cs_std::{prelude::Boolean, ToBitsGadget};
use simpleworks::gadgets::{ConstraintF, UInt8Gadget};

pub fn _to_bits_be(bits: &[Boolean<ConstraintF>]) -> Result<Vec<Boolean<ConstraintF>>> {
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

pub fn u8_add(augend: &UInt8Gadget, addend: &UInt8Gadget) -> Result<UInt8Gadget> {
    let augend = augend.to_bits_be()?;
    let addend = addend.to_bits_be()?;
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
            carry.xor(augend_bit)?.xor(&addend_bit)?;
        // To simplify things, the variable carry acts for both the carry in and
        // the carry out.
        // The carry out is augend & addend when the carry in is 0, and it is
        // augend | addend when the carry in is 1.
        // carry = carry.not()
        carry = (carry.not().and(&(augend_bit.and(&addend_bit)?))?)
            .or(&(carry.and(&(augend_bit.or(&addend_bit)?))?))?;
    }
    sum.reverse();
    Ok(UInt8Gadget::from_bits_le(&sum))
}

#[cfg(test)]
mod tests {
    use super::add;
    use ark_r1cs_std::{prelude::Boolean, R1CSVar};
    use simpleworks::gadgets::{ConstraintF};

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
}
