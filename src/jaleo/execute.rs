use super::{credits, Transition, Identifier, PrivateKey, Program};
use crate::{jaleo::program_is_coinbase, variable_type::VariableType, ProgramBuild};
use anyhow::{anyhow, ensure, Result};
use ark_std::rand::rngs::StdRng;
use log::debug;
use simpleworks::{
    marlin::serialization::{deserialize_proof, serialize_proof},
    types::value::SimpleworksValueType,
};

const MAX_INPUTS: usize = 8;
const MAX_OUTPUTS: usize = 8;

pub fn verify_execution(transition: &Transition, program_build: &ProgramBuild) -> Result<()> {
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
    let (_proving_key, verifying_key) = program_build
        .map
        .get(&transition.function_name)
        .ok_or_else(|| anyhow!("missing verifying key"))?;

    // Decode and deserialize the proof.
    let proof_bytes = hex::decode(&transition.proof)?;
    let proof = deserialize_proof(proof_bytes)?;

    let inputs: Vec<SimpleworksValueType> = transition
        .inputs
        .iter()
        .filter_map(|i| match i {
            VariableType::Public(_, value) => Some(value.clone()),
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
    inputs: &[SimpleworksValueType],
    private_key: &PrivateKey,
    rng: &mut StdRng,
) -> Result<Vec<Transition>> {
    execution(&credits()?, function_name, inputs, private_key, rng)
}

pub fn execution(
    program: &Program,
    function_name: &Identifier,
    inputs: &[SimpleworksValueType],
    _private_key: &PrivateKey,
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

    let (inputs, outputs, proof) = crate::execute_function(&function, inputs, rng)?;

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
