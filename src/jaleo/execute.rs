use super::{credits, Function, Identifier, PrivateKey, Program, Transition, VerifyingKeyMap};
use crate::{
    jaleo::{program_is_coinbase, Record, UserInputValueType},
    variable_type::VariableType,
    CircuitInputType, CircuitOutputType, SimpleFunctionVariables,
};
use anyhow::{anyhow, bail, ensure, Result};
use ark_r1cs_std::R1CSVar;
use ark_std::rand::rngs::StdRng;
use indexmap::IndexMap;
use log::debug;
use simpleworks::marlin::serialization::{deserialize_proof, serialize_proof};

use crate::CircuitIOType::{
    SimpleAddress, SimpleRecord, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

const MAX_INPUTS: usize = 8;
const MAX_OUTPUTS: usize = 8;

pub fn verify_execution(
    transition: &Transition,
    verifying_key_map: &VerifyingKeyMap,
) -> Result<()> {
    // Verify each transition.
    log::debug!(
        "Verifying transition for {}/{}...",
        transition.program_id,
        transition.function_name
    );

    // this check also rules out coinbase executions (e.g. credits genesis function)
    ensure!(
        transition.fee >= 0,
        "The execution fee is negative, cannot create credits"
    );

    // Ensure an external execution isn't attempting to create credits
    // The assumption at this point is that credits can only be created in the genesis block
    // We may revisit if we add validator rewards, at which point some credits may be minted, although
    // still not by external function calls
    ensure!(
        !program_is_coinbase(&transition.program_id, &transition.function_name),
        "Coinbase functions cannot be called"
    );
    // // Ensure the transition ID is correct.
    // ensure!(
    //     **transition == transition.to_root()?,
    //     "The transition ID is incorrect"
    // );
    // Ensure the number of inputs is within the allowed range.
    ensure!(
        transition.inputs.len() <= MAX_INPUTS,
        "Transition exceeded maximum number of inputs"
    );
    // Ensure the number of outputs is within the allowed range.
    ensure!(
        transition.outputs.len() <= MAX_OUTPUTS,
        "Transition exceeded maximum number of outputs"
    );
    // // Ensure each input is valid.
    // if transition
    //     .inputs
    //     .iter()
    //     .enumerate()
    //     .any(|(index, input)| !input.verify(transition.tcm(), index))
    // {
    //     bail!("Failed to verify a transition input")
    // }
    // // Ensure each output is valid.
    // let num_inputs = transition.inputs.len();
    // if transition
    //     .outputs
    //     .iter()
    //     .enumerate()
    //     .any(|(index, output)| !output.verify(transition.tcm(), num_inputs + index))
    // {
    //     bail!("Failed to verify a transition output")
    // }

    // Retrieve the verifying key.
    let verifying_key = verifying_key_map
        .map
        .get(&transition.function_name)
        .ok_or_else(|| anyhow!("missing verifying key"))?;

    // Decode and deserialize the proof.
    let proof_bytes = hex::decode(&transition.proof)?;
    let proof = deserialize_proof(proof_bytes)?;

    let inputs: Vec<UserInputValueType> = transition
        .inputs
        .iter()
        .filter_map(|i| match i {
            VariableType::Public(value) => Some(value.clone()),
            _ => None,
        })
        .collect();

    // Ensure the proof is valid.
    ensure!(
        crate::verify_proof(
            verifying_key.clone(),
            &inputs,
            &proof,
            &mut simpleworks::marlin::generate_rand()
        )?,
        "Transition is invalid"
    );
    Ok(())
}

pub fn credits_execution(
    function_name: &Identifier,
    inputs: &[UserInputValueType],
    private_key: &PrivateKey,
    rng: &mut StdRng,
) -> Result<Vec<Transition>> {
    execution(&credits()?, function_name, inputs, private_key, rng)
}

pub fn execution(
    program: &Program,
    function_name: &Identifier,
    inputs: &[UserInputValueType],
    private_key: &PrivateKey,
    rng: &mut StdRng,
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

    let (compiled_function_variables, proof) = crate::execute_function(&function, inputs, rng)?;

    let inputs = process_circuit_inputs(&function, &compiled_function_variables, private_key)?;
    let outputs = process_circuit_outputs(&function, &compiled_function_variables)?;

    let bytes_proof = serialize_proof(proof)?;
    let encoded_proof = hex::encode(bytes_proof);

    let transition = Transition {
        program_id: program.id().to_string(),
        function_name: function_name.to_string(),
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
pub(crate) fn process_circuit_inputs(
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
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(r.owner.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        let record = Record::new(
                            primitive_bytes,
                            r.gates.value()?,
                            r.entries,
                            Some(r.nonce),
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
pub(crate) fn process_circuit_outputs(
    function: &Function,
    program_variables: &SimpleFunctionVariables,
) -> Result<CircuitOutputType> {
    let mut circuit_outputs = IndexMap::new();
    function.outputs().iter().try_for_each(|o| {
        let register = o.register().to_string();
        let program_variable = program_variables
            .get(&register)
            .ok_or_else(|| anyhow!("Register \"{register}\" not found"))
            .and_then(|r| {
                r.clone()
                    .ok_or_else(|| anyhow!("Register \"{register}\" not assigned"))
            })?;

        circuit_outputs.insert(register, {
            if program_variable.is_witness()? {
                match program_variable {
                    SimpleUInt8(v) => VariableType::Private(UserInputValueType::U8(v.value()?)),
                    SimpleUInt16(v) => VariableType::Private(UserInputValueType::U16(v.value()?)),
                    SimpleUInt32(v) => VariableType::Private(UserInputValueType::U32(v.value()?)),
                    SimpleUInt64(v) => VariableType::Private(UserInputValueType::U64(v.value()?)),
                    SimpleRecord(r) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(r.owner.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        let record = Record::new(
                            primitive_bytes,
                            r.gates.value()?,
                            r.entries,
                            Some(r.nonce),
                        );
                        VariableType::Record(None, record)
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
                }
            }
        });
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(circuit_outputs)
}
