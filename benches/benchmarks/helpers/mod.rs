#[cfg(test)]
// This allow macro is added because of a bug.
#[allow(dead_code)]
pub mod test_helpers {
    use anyhow::Result;
    use ark_r1cs_std::{prelude::EqGadget, R1CSVar};
    use snarkvm::prelude::{Group, Testnet3};
    use vmtropy::{
        helpers,
        jaleo::{self, Address, PrivateKey},
        CircuitIOType, VMRecordEntriesMap,
    };

    pub fn address() -> (String, [u8; 63]) {
        let rng = &mut rand::thread_rng();
        let private_key = PrivateKey::new(rng).unwrap();
        let primitive_address = Address::try_from(private_key).unwrap().to_string();

        let address_bytes = helpers::to_address(primitive_address.clone());
        (primitive_address, address_bytes)
    }

    pub fn read_program(instruction: &str) -> Result<String> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(&format!("programs/{instruction}/main.aleo"));
        let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        Ok(program)
    }

    pub fn input_record(
        owner: jaleo::AddressBytes,
        gates: u64,
        data: jaleo::RecordEntriesMap,
        nonce: Group<Testnet3>,
    ) -> jaleo::UserInputValueType {
        jaleo::UserInputValueType::Record(jaleo::Record {
            owner,
            gates,
            data,
            nonce: Some(nonce),
        })
    }

    pub fn sample_nonce() -> Group<Testnet3> {
        helpers::random_nonce()
    }

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
