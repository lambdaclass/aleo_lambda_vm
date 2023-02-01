use super::{credits, Function, Identifier, PrivateKey, Program, Transition};
use crate::{
    helpers::to_address,
    jaleo::{program_is_coinbase, Record, UserInputValueType},
    variable_type::VariableType,
    CircuitInputType, CircuitOutputType, SimpleFunctionVariables,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_r1cs_std::R1CSVar;
use indexmap::IndexMap;
use log::debug;
use simpleworks::marlin::serialization::serialize_proof;
use snarkvm::prelude::{Scalar, Uniform};

use crate::CircuitIOType::{
    SimpleAddress, SimpleBoolean, SimpleField, SimpleRecord, SimpleUInt16, SimpleUInt32,
    SimpleUInt64, SimpleUInt8,
};

pub fn credits_execution(
    function_name: &Identifier,
    inputs: &[UserInputValueType],
    private_key: &PrivateKey,
) -> Result<Vec<Transition>> {
    execution(&credits()?, function_name, inputs, private_key)
}

pub fn execution(
    program: &Program,
    function_name: &Identifier,
    inputs: &[UserInputValueType],
    private_key: &PrivateKey,
) -> Result<Vec<Transition>> {
    ensure!(
        !program_is_coinbase(&program.id().to_string(), &function_name.to_string()),
        "Coinbase functions cannot be called"
    );

    debug!(
        "executing program {} function {} inputs {:?}",
        program, function_name, inputs
    );

    let function = program
        .get_function(function_name)
        .map_err(|e| anyhow!("{}", e))?;

    let (compiled_function_variables, proof) =
        crate::execute_function(program, &function.to_string(), inputs)?;

    let inputs = process_circuit_inputs(&function, &compiled_function_variables, private_key)?;
    let outputs = process_circuit_outputs(&function, &compiled_function_variables)?;

    let bytes_proof = serialize_proof(proof)?;
    let encoded_proof = hex::encode(bytes_proof);

    let transition = Transition {
        program_id: *program.id(),
        function_name: *function_name,
        inputs: inputs.into_values().collect::<Vec<VariableType>>(),
        outputs: outputs.into_values().collect::<Vec<VariableType>>(),
        proof: encoded_proof,
        fee: 0,
    };

    Ok(vec![transition])
}

/// Returns a hash map with the circuit inputs of a given function and its variables.
///
/// # Parameters
/// - `function` - function to be analyzed.
/// - `program_variables` - variables of the function.
///  
/// # Returns
/// - `IndexMap` of the Circuit Output.
///
pub fn process_circuit_inputs(
    function: &Function,
    program_variables: &SimpleFunctionVariables,
    private_key: &PrivateKey,
) -> Result<CircuitInputType> {
    let mut circuit_inputs = IndexMap::new();
    function.inputs().iter().try_for_each(|o| {
        let register = o.register().to_string();
        let program_variable = program_variables
            .get(&register)
            .ok_or_else(|| anyhow!("Register \"{register}\" not found"))
            .and_then(|r| {
                r.clone()
                    .ok_or_else(|| anyhow!("Register \"{register}\" not assigned"))
            })?;

        circuit_inputs.insert(register, {
            if program_variable.is_witness()? {
                match program_variable {
                    SimpleUInt8(v) => VariableType::Private(UserInputValueType::U8(v.value()?)),
                    SimpleUInt16(v) => VariableType::Private(UserInputValueType::U16(v.value()?)),
                    SimpleUInt32(v) => VariableType::Private(UserInputValueType::U32(v.value()?)),
                    SimpleUInt64(v) => VariableType::Private(UserInputValueType::U64(v.value()?)),
                    SimpleRecord(r) => {
                        // VMRecord to JAleoRecord
                        let mut primitive_entries = IndexMap::new();
                        for (k, v) in r.entries {
                            let primitive_value = match v {
                                SimpleUInt8(v) => UserInputValueType::U8(v.value()?),
                                SimpleUInt16(v) => UserInputValueType::U16(v.value()?),
                                SimpleUInt32(v) => UserInputValueType::U32(v.value()?),
                                SimpleUInt64(v) => UserInputValueType::U64(v.value()?),
                                SimpleRecord(_) => bail!("Nested records are not supported"),
                                SimpleAddress(v) => {
                                    UserInputValueType::Address(to_address(v.value()?))
                                }
                                SimpleBoolean(b) => UserInputValueType::Boolean(b.value()?),
                                SimpleField(f) => UserInputValueType::Field(f.value()?),
                            };
                            primitive_entries.insert(k, primitive_value);
                        }
                        let record = Record::new(
                            to_address(r.owner.value()?),
                            r.gates.value()?,
                            primitive_entries,
                            r.nonce,
                        );
                        VariableType::Record(Some(record.serial_number(private_key)?), record)
                    }
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        VariableType::Private(UserInputValueType::Address(primitive_bytes))
                    }
                    SimpleBoolean(b) => {
                        VariableType::Private(UserInputValueType::Boolean(b.value()?))
                    }
                    SimpleField(f) => VariableType::Private(UserInputValueType::Field(f.value()?)),
                }
            } else {
                match program_variable {
                    SimpleUInt8(v) => VariableType::Public(UserInputValueType::U8(v.value()?)),
                    SimpleUInt16(v) => VariableType::Public(UserInputValueType::U16(v.value()?)),
                    SimpleUInt32(v) => VariableType::Public(UserInputValueType::U32(v.value()?)),
                    SimpleUInt64(v) => VariableType::Public(UserInputValueType::U64(v.value()?)),
                    SimpleRecord(_) => bail!("Records cannot be public"),
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        VariableType::Public(UserInputValueType::Address(primitive_bytes))
                    }
                    SimpleBoolean(b) => {
                        VariableType::Public(UserInputValueType::Boolean(b.value()?))
                    }
                    SimpleField(f) => VariableType::Public(UserInputValueType::Field(f.value()?)),
                }
            }
        });
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(circuit_inputs)
}

/// Returns a hash map with the circuit outputs of a given function and its variables.
///
/// # Parameters
/// - `function` - function to be analyzed.
/// - `program_variables` - variables of the function.
///  
/// # Returns
/// - `IndexMap` of the Circuit Output.
///
pub fn process_circuit_outputs(
    function: &Function,
    program_variables: &SimpleFunctionVariables,
) -> Result<CircuitOutputType> {
    let mut circuit_outputs = IndexMap::new();
    function.outputs().iter().try_for_each(|o| {
        let register_identifier = o.register().to_string();
        // output can be of the form 'r7.owner', so split and get the first section
        let register_split: Vec<&str> = register_identifier.split('.').collect();

        ensure!(
            register_split.len() <= 2,
            "Output field {register_identifier} was not specified correctly"
        );

        let register_variable = match register_split.first() {
            Some(register_variable) => register_variable,
            None => {
                return Err(anyhow!(
                    "Could not get the variable in Output field: {register}"
                ))
            }
        };
        let program_variable = program_variables
            .get(*register_variable)
            .ok_or_else(|| anyhow!("Register \"{register}\" not found"))
            .and_then(|r| {
                // if desired output is a record field (ie `output r0.gates as u64.public`),
                // get the field; get the whole register otherwise
                let register_value = match (r, register_split.len() == 2) {
                    (Some(SimpleRecord(record)), true) => {
                        if let Some(key) = register_split.get(1) {
                            match *key {
                                "owner" => Some(SimpleAddress(record.owner.clone())),
                                "gates" => Some(SimpleUInt64(record.gates.clone())),
                                _ => record.entries.get(*key).cloned(),
                            }
                        } else {
                            None
                        }
                    }
                    _ => r.clone(),
                };
                register_value
                    .ok_or_else(|| anyhow!("Register \"{register_identifier}\" not assigned"))
            })?;

        circuit_outputs.insert(register_identifier, {
            if program_variable.is_witness()? {
                match program_variable {
                    SimpleUInt8(v) => VariableType::Private(UserInputValueType::U8(v.value()?)),
                    SimpleUInt16(v) => VariableType::Private(UserInputValueType::U16(v.value()?)),
                    SimpleUInt32(v) => VariableType::Private(UserInputValueType::U32(v.value()?)),
                    SimpleUInt64(v) => VariableType::Private(UserInputValueType::U64(v.value()?)),
                    SimpleRecord(r) => {
                        // VMRecord to JAleoRecord
                        let mut primitive_entries = IndexMap::new();
                        for (k, v) in r.entries {
                            let primitive_value = match v {
                                SimpleUInt8(v) => UserInputValueType::U8(v.value()?),
                                SimpleUInt16(v) => UserInputValueType::U16(v.value()?),
                                SimpleUInt32(v) => UserInputValueType::U32(v.value()?),
                                SimpleUInt64(v) => UserInputValueType::U64(v.value()?),
                                SimpleRecord(_) => bail!("Nested records are not supported"),
                                SimpleAddress(v) => {
                                    UserInputValueType::Address(to_address(v.value()?))
                                }
                                SimpleBoolean(b) => UserInputValueType::Boolean(b.value()?),
                                SimpleField(f) => UserInputValueType::Field(f.value()?),
                            };
                            primitive_entries.insert(k, primitive_value);
                        }
                        let mut record = Record::new(
                            to_address(r.owner.value()?),
                            r.gates.value()?,
                            primitive_entries,
                            None,
                        );
                        let rng = &mut rand::thread_rng();
                        let randomizer = Scalar::rand(rng);

                        let encrypted_record = record.encrypt(randomizer)?;
                        // NOTE: ORDER HERE IS EXTREMELY IMPORTANT
                        // The commitment MUST be calculated after encryption, otherwise
                        // the nonce is not set and the commitment turns out wrong.
                        let commitment = record.commitment()?;
                        VariableType::EncryptedRecord((commitment, encrypted_record))
                    }
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        VariableType::Private(UserInputValueType::Address(primitive_bytes))
                    }
                    SimpleBoolean(b) => {
                        VariableType::Private(UserInputValueType::Boolean(b.value()?))
                    }
                    SimpleField(f) => VariableType::Private(UserInputValueType::Field(f.value()?)),
                }
            } else {
                match program_variable {
                    SimpleUInt8(v) => VariableType::Private(UserInputValueType::U8(v.value()?)),
                    SimpleUInt16(v) => VariableType::Private(UserInputValueType::U16(v.value()?)),
                    SimpleUInt32(v) => VariableType::Private(UserInputValueType::U32(v.value()?)),
                    SimpleUInt64(v) => VariableType::Private(UserInputValueType::U64(v.value()?)),
                    SimpleRecord(_) => bail!("Records cannot be public"),
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        VariableType::Private(UserInputValueType::Address(primitive_bytes))
                    }
                    SimpleBoolean(b) => {
                        VariableType::Public(UserInputValueType::Boolean(b.value()?))
                    }
                    SimpleField(f) => VariableType::Public(UserInputValueType::Field(f.value()?)),
                }
            }
        });
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(circuit_outputs)
}
