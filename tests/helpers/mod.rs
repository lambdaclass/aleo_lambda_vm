#[cfg(test)]
// This allow macro is added because of a bug.
#[allow(dead_code)]
pub mod test_helpers {
    use anyhow::{anyhow, bail, Result};
    use ark_ff::UniformRand;
    use ark_r1cs_std::{prelude::EqGadget, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::ConstraintF;
    use snarkvm::prelude::{LiteralType, Parser, PlaintextType, ValueType};
    use vmtropy::{
        build_function,
        helpers::{self, aleo_entries_to_vm_entries},
        jaleo::{self, Identifier, Program, Record, UserInputValueType},
        CircuitIOType, ProgramBuild, VMRecordEntriesMap,
    };

    pub fn address(n: u64) -> (String, [u8; 63]) {
        let primitive_address =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
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
        nonce: ConstraintF,
    ) -> jaleo::UserInputValueType {
        jaleo::UserInputValueType::Record(jaleo::Record {
            owner,
            gates,
            data,
            nonce,
        })
    }

    pub fn sample_nonce() -> ConstraintF {
        ConstraintF::rand(&mut ark_std::rand::thread_rng())
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

    // NOTE: This function wraps the one in src/lib.rs because are wrapping
    // default_user_inputs originally because of the TODO of the original default_user_inputs
    // function.
    // TODO: Remove this when the issue is resolved.
    pub fn build_program_for_div(program_string: &str) -> Result<(Program, ProgramBuild)> {
        let mut rng = simpleworks::marlin::generate_rand();
        let universal_srs =
            simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, &mut rng)?;

        let (_, program) = Program::parse(program_string).map_err(|e| anyhow!("{}", e))?;

        let mut program_build = ProgramBuild {
            map: IndexMap::new(),
        };
        for (function_name, function) in program.functions() {
            let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();
            let inputs = default_user_inputs_for_div(&program, function_name)?;
            let (function_proving_key, function_verifying_key) = match build_function(
                &program,
                function,
                &inputs,
                constraint_system.clone(),
                &universal_srs,
                &mut vmtropy::helpers::function_variables(function, constraint_system.clone())?,
            ) {
                Ok((function_proving_key, function_verifying_key)) => {
                    (function_proving_key, function_verifying_key)
                }
                Err(e) => {
                    bail!(
                        "Couldn't build function \"{}\": {}",
                        function_name.to_string(),
                        e
                    );
                }
            };
            program_build.map.insert(
                *function.name(),
                (function_proving_key, function_verifying_key),
            );
        }

        Ok((program, program_build))
    }

    // NOTE: Same as above.
    pub fn default_user_inputs_for_div(
        program: &Program,
        function_name: &Identifier,
    ) -> Result<Vec<UserInputValueType>> {
        let mut default_user_inputs: Vec<UserInputValueType> = Vec::new();
        for function_input in program.get_function(function_name)?.inputs() {
            let default_user_input = match function_input.value_type() {
                // UInt
                ValueType::Public(PlaintextType::Literal(LiteralType::U8))
                | ValueType::Private(PlaintextType::Literal(LiteralType::U8)) => {
                    UserInputValueType::U8(1_u8)
                }
                ValueType::Public(PlaintextType::Literal(LiteralType::U16))
                | ValueType::Private(PlaintextType::Literal(LiteralType::U16)) => {
                    UserInputValueType::U16(1_u16)
                }
                ValueType::Public(PlaintextType::Literal(LiteralType::U32))
                | ValueType::Private(PlaintextType::Literal(LiteralType::U32)) => {
                    UserInputValueType::U32(1_u32)
                }
                ValueType::Public(PlaintextType::Literal(LiteralType::U64))
                | ValueType::Private(PlaintextType::Literal(LiteralType::U64)) => {
                    UserInputValueType::U64(1_u64)
                }
                ValueType::Public(PlaintextType::Literal(LiteralType::U128))
                | ValueType::Private(PlaintextType::Literal(LiteralType::U128)) => {
                    UserInputValueType::U128(1_u128)
                }
                // Address
                ValueType::Public(PlaintextType::Literal(LiteralType::Address))
                | ValueType::Private(PlaintextType::Literal(LiteralType::Address)) => {
                    UserInputValueType::Address(
                        *b"aleo11111111111111111111111111111111111111111111111111111111111",
                    )
                }
                // Field
                ValueType::Public(PlaintextType::Literal(LiteralType::Field))
                | ValueType::Private(PlaintextType::Literal(LiteralType::Field)) => {
                    UserInputValueType::Field(ConstraintF::default())
                }
                // Boolean
                ValueType::Public(PlaintextType::Literal(LiteralType::Boolean))
                | ValueType::Private(PlaintextType::Literal(LiteralType::Boolean)) => {
                    UserInputValueType::Boolean(false)
                }
                // Unsupported Cases
                ValueType::Public(v) | ValueType::Private(v) => {
                    println!("UNSUPPORTED TYPE: {v:?}");
                    bail!("Unsupported type")
                }
                // Records
                ValueType::Record(record_identifier) => {
                    let aleo_record = program.get_record(record_identifier)?;
                    let aleo_record_entries = aleo_record.entries();
                    UserInputValueType::Record(Record {
                        owner: *b"aleo11111111111111111111111111111111111111111111111111111111111",
                        gates: u64::default(),
                        data: aleo_entries_to_vm_entries(aleo_record_entries)?,
                        nonce: ConstraintF::default(),
                    })
                }
                // Constant Types
                ValueType::Constant(_) => bail!("Constant types are not supported"),
                // External Records
                ValueType::ExternalRecord(_) => bail!("ExternalRecord types are not supported"),
            };
            default_user_inputs.push(default_user_input);
        }
        Ok(default_user_inputs)
    }
}
