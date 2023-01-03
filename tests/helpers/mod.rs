#[cfg(test)]
pub mod test_helpers {
    use ark_ff::UniformRand;
    use ark_r1cs_std::{prelude::EqGadget, R1CSVar};
    use simpleworks::gadgets::ConstraintF;
    use vmtropy::{helpers, jaleo, CircuitIOType, VMRecordEntriesMap};

    pub fn address(n: u64) -> (String, [u8; 63]) {
        let primitive_address =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        let address_bytes = helpers::to_address(primitive_address.clone());
        (primitive_address, address_bytes)
    }

    // This allow macro is added because of a bug, you could see that his function
    // is used in credits_aleo.rs
    #[allow(dead_code)]
    pub fn input_record(
        owner: jaleo::AddressBytes,
        gates: u64,
        data: jaleo::RecordEntriesMap,
        nonce: ConstraintF,
    ) -> jaleo::UserInputValueType {
        jaleo::UserInputValueType::Record(jaleo::Record {
            owner,
            gates,
            data,
            nonce,
        })
    }

    // This allow macro is added because of a bug, you could see that his function
    // is used in credits_aleo.rs
    #[allow(dead_code)]
    pub fn sample_nonce() -> ConstraintF {
        ConstraintF::rand(&mut ark_std::rand::thread_rng())
    }

    // This allow macro is added because of a bug, you could see that his function
    // is used in credits_aleo.rs
    #[allow(dead_code)]
    pub fn vm_record_entries_are_equal(
        some_entries: &VMRecordEntriesMap,
        other_entries: VMRecordEntriesMap,
    ) -> bool {
        let mut entries_are_equal = true;
        for ((self_k, self_v), (other_k, other_v)) in some_entries.iter().zip(&other_entries) {
            entries_are_equal &= {
                let values_are_equal = match (self_v, other_v) {
                    (CircuitIOType::SimpleUInt8(self_v), CircuitIOType::SimpleUInt8(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt16(self_v), CircuitIOType::SimpleUInt16(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt32(self_v), CircuitIOType::SimpleUInt32(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleUInt64(self_v), CircuitIOType::SimpleUInt64(other_v)) => {
                        match self_v.is_eq(other_v) {
                            Ok(v) => v.value().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                    (CircuitIOType::SimpleRecord(self_v), CircuitIOType::SimpleRecord(other_v)) => {
                        vmtropy::Record::eq(self_v, other_v)
                    }
                    (
                        CircuitIOType::SimpleAddress(self_v),
                        CircuitIOType::SimpleAddress(other_v),
                    ) => match self_v.is_eq(other_v) {
                        Ok(v) => v.value().unwrap_or(false),
                        Err(_) => false,
                    },
                    (_, _) => false,
                };
                let keys_are_equal = *self_k == *other_k;
                values_are_equal && keys_are_equal
            }
        }
        entries_are_equal
    }
}
