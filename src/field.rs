pub type Field = ark_ed_on_bls12_381::Fq;
use core::cmp::min;

use ark_serialize::CanonicalDeserialize;

const MODULUS_BITS: u16 = 381;
const REPR_SHAVE_BITS: u32 = 5;

fn from_random_bytes_with_flags(bytes: &[u8]) -> Option<(Field, Field)> {
    {
        let mut result_bytes = [0_u8; 4 * 8 + 1];
        result_bytes
            .iter_mut()
            .zip(bytes)
            .for_each(|(result, input)| {
                *result = *input;
            });
        let last_limb_mask = (u64::MAX >> REPR_SHAVE_BITS).to_le_bytes();
        let mut last_bytes_mask = [0_u8; 9];
        last_bytes_mask[..8].copy_from_slice(&last_limb_mask);
        let output_byte_size = usize::from((MODULUS_BITS + 7) / 8);
        let flag_location = output_byte_size - 1;
        let flag_location_in_last_limb = flag_location - (8 * (4 - 1));
        let last_bytes = &mut result_bytes[8 * (4 - 1)..];
        let flags_mask = u8::MAX.checked_shl(8).unwrap_or(0);
        let mut flags: u8 = 0;
        for (i, (b, m)) in last_bytes.iter_mut().zip(&last_bytes_mask).enumerate() {
            if i == flag_location_in_last_limb {
                flags = *b & flags_mask;
            }
            *b &= m;
        }
        Field::deserialize_uncompressed(&result_bytes[..(4 * 8)])
            .ok()
            .and_then(|f| Some(Field::from(flags)).map(|flag| (f, flag)))
    }
}

#[inline]
fn from_random_bytes(bytes: &[u8]) -> Option<Field> {
    from_random_bytes_with_flags(bytes).map(|f| f.0)
}

// ******************************
/// Reads bytes in big-endian, and converts them to a field element.
/// If the bytes are larger than the modulus, it will reduce them.
fn from_bytes_be_mod_order(bytes: &[u8]) -> Option<Field> {
    let num_modulus_bytes = usize::from((MODULUS_BITS + 7) / 8);
    let num_bytes_to_directly_convert = min(num_modulus_bytes - 1, bytes.len());
    let (leading_bytes, remaining_bytes) = bytes.split_at(num_bytes_to_directly_convert);
    // Copy the leading big-endian bytes directly into a field element.
    // The number of bytes directly converted must be less than the
    // number of bytes needed to represent the modulus, as we must begin
    // modular reduction once the data is of the same number of bytes as the modulus.
    let mut bytes_to_directly_convert = leading_bytes.to_vec();
    bytes_to_directly_convert.reverse();
    // Guaranteed to not be None, as the input is less than the modulus size.
    let mut res = from_random_bytes(&bytes_to_directly_convert)?;

    // Update the result, byte by byte.
    // We go through existing field arithmetic, which handles the reduction.
    let window_size = Field::from(256_u64);
    for byte in remaining_bytes {
        res *= window_size;
        res += Field::from(*byte);
    }
    Some(res)
}

/// Reads bytes in little-endian, and converts them to a field element.
/// If the bytes are larger than the modulus, it will reduce them.
fn from_bytes_le_mod_order(bytes: &[u8]) -> Option<Field> {
    let mut bytes_copy = bytes.to_vec();
    bytes_copy.reverse();
    from_bytes_be_mod_order(&bytes_copy)
}
// ******************************

/// Initializes a new field as a domain separator.
pub fn new_domain_separator(domain: &str) -> Option<Field> {
    Some(Field::new(
        from_bytes_le_mod_order(domain.as_bytes())?.into(),
    ))
}
