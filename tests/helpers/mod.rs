#[cfg(test)]
pub mod test_helpers {
    use ark_ff::UniformRand;
    use simpleworks::gadgets::ConstraintF;
    use vmtropy::{helpers, jaleo};

    pub fn address(n: u64) -> (String, [u8; 63]) {
        let primitive_address =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        let address_bytes = helpers::to_address(primitive_address.clone());
        (primitive_address, address_bytes)
    }

    pub fn input_record(
        owner: jaleo::AddressBytes,
        gates: u64,
        entries: jaleo::RecordEntriesMap,
        nonce: ConstraintF,
    ) -> jaleo::UserInputValueType {
        jaleo::UserInputValueType::Record(jaleo::Record {
            owner,
            gates,
            entries,
            nonce,
        })
    }

    pub fn sample_nonce() -> ConstraintF {
        ConstraintF::rand(&mut ark_std::rand::thread_rng())
    }
}
