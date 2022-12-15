use crate::jaleo::RecordEntriesMap;

use super::{AddressGadget, UInt64Gadget};
use anyhow::Result;
use ark_r1cs_std::R1CSVar;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};

fn hashmap_to_string(hashmap: &RecordEntriesMap) -> Result<String> {
    let mut ret = String::new();
    ret.push('{');

    for (i, (k, v)) in hashmap.iter().enumerate() {
        ret.push_str(&format!("\"{}\":\"{}\"", k, v));
        if i > 0 {
            ret.push(',');
        }
    }

    ret.push('}');
    Ok(ret)
}

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: AddressGadget,
    pub gates: UInt64Gadget,
    // custom fields
    pub entries: RecordEntriesMap,
    pub nonce: ConstraintF,
}

impl Serialize for Record {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Record", 4)?;
        state.serialize_field("owner", &self.owner)?;
        state.serialize_field(
            "gates",
            &self.gates.value().map_err(|e| {
                serde::ser::Error::custom(format!("Error serializing VM Record gates: {e:?}"))
            })?,
        )?;
        state.serialize_field(
            "entries",
            &hashmap_to_string(&self.entries).map_err(|e| {
                serde::ser::Error::custom(format!("Error serializing VM Record entries: {e:?}"))
            })?,
        )?;
        state.serialize_field(
            "nonce",
            &hex::encode(serialize_field_element(self.nonce).map_err(|e| {
                serde::ser::Error::custom(format!("Error serializing VM Record nonce: {e:?}"))
            })?),
        )?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressGadget, Record, RecordEntriesMap, UInt64Gadget};
    use crate::jaleo::UserInputValueType;
    use ark_ff::UniformRand;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_std::rand::thread_rng;
    use simpleworks::gadgets::ConstraintF;

    #[test]
    fn test_serialization() {
        let cs = ConstraintSystem::<ark_ed_on_bls12_381::Fq>::new_ref();
        let owner = AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
            Ok(b"aleo11111111111111111111111111111111111111111111111111111111111")
        })
        .unwrap();
        let gates = UInt64Gadget::new_witness(Namespace::new(cs, None), || Ok(1)).unwrap();
        let mut entries = RecordEntriesMap::new();
        entries.insert("age".to_owned(), UserInputValueType::U8(35));

        let record = Record {
            owner,
            gates,
            entries,
            nonce: ConstraintF::rand(&mut thread_rng()),
        };

        let serialized = serde_json::to_string(&record).unwrap();

        println!("s: {}", serialized);
    }
}
