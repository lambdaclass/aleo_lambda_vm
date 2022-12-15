pub type Field = ark_ed_on_bls12_381::Fq;
use core::cmp::min;

const MODULUS_BITS: u32 = 381;
const REPR_SHAVE_BITS: u32 = 5;

fn from_random_bytes_with_flags(
    bytes: &[u8],
) -> Option<(Self, F)> {

    {
        let mut result_bytes = [0u8; 4 * 8 + 1];
        result_bytes
            .iter_mut()
            .zip(bytes)
            .for_each(|(result, input)| {
                *result = *input;
            });
        let last_limb_mask = (u64::MAX >> REPR_SHAVE_BITS).to_le_bytes();
        let mut last_bytes_mask = [0u8; 9];
        last_bytes_mask[..8].copy_from_slice(&last_limb_mask);
        let output_byte_size = ((MODULUS_BITS + 7) / 8) as usize;
        let flag_location = output_byte_size - 1;
        let flag_location_in_last_limb = flag_location - (8 * (4 - 1));
        let last_bytes = &mut result_bytes[8 * (4 - 1)..];
        let flags_mask = u8::MAX
            .checked_shl(8)
            .unwrap_or(0);
        let mut flags: u8 = 0;
        for (i, (b, m)) in last_bytes
            .iter_mut()
            .zip(&last_bytes_mask)
            .enumerate()
        {
            if i == flag_location_in_last_limb {
                flags = *b & flags_mask;
            }
            *b &= m;
        }
        Self::deserialize_uncompressed(&result_bytes[..(4 * 8)])
            .ok()
            .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
    }.flatten()

        
}

// ******************************
    /// Reads bytes in big-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_bytes_be_mod_order(bytes: &[u8]) -> Field {
        let num_modulus_bytes = ((MODULUS_BITS + 7) / 8) as usize;
        let num_bytes_to_directly_convert = min(num_modulus_bytes - 1, bytes.len());
        let (leading_bytes, remaining_bytes) = bytes.split_at(num_bytes_to_directly_convert);
        // Copy the leading big-endian bytes directly into a field element.
        // The number of bytes directly converted must be less than the
        // number of bytes needed to represent the modulus, as we must begin
        // modular reduction once the data is of the same number of bytes as the modulus.
        let mut bytes_to_directly_convert = leading_bytes.to_vec();
        bytes_to_directly_convert.reverse();
        // Guaranteed to not be None, as the input is less than the modulus size.
        let mut res = Self::from_random_bytes(&bytes_to_directly_convert).unwrap();

        // Update the result, byte by byte.
        // We go through existing field arithmetic, which handles the reduction.
        let window_size = Field::from(256u64);
        for byte in remaining_bytes {
            res *= window_size;
            res += Field::from(*byte);
        }
        res
    }

    /// Reads bytes in little-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_bytes_le_mod_order(bytes: &[u8]) -> Field {
        let mut bytes_copy = bytes.to_vec();
        bytes_copy.reverse();
        from_bytes_be_mod_order(&bytes_copy)
    }
// ******************************
