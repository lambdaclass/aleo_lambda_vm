use crate::{
    circuit_io_type::{
        SimpleAddress, SimpleRecord, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    },
    instructions,
    record::Record,
    CircuitOutputType, FunctionKeys, SimpleFunctionVariables, xxx::XXX,
};
use anyhow::{anyhow, bail, Result};
use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace};
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget},
    marlin::UniversalSRS,
    types::value::{RecordEntriesMap, SimpleworksValueType},
};
use snarkvm::prelude::{
    Function, Instruction, LiteralType, Operand, PlaintextType, Register, Testnet3, ValueType,
};

/// Builds a function, which means generating its proving and verifying keys.
pub fn build_function(
    function: &Function<Testnet3>,
    user_inputs: &[SimpleworksValueType],
    constraint_system: ConstraintSystemRef<ConstraintF>,
    universal_srs: &UniversalSRS,
    function_variables: &mut SimpleFunctionVariables,
) -> Result<FunctionKeys> {
    process_inputs(
        function,
        &constraint_system,
        user_inputs,
        function_variables,
    )?;
    process_outputs(function, function_variables)?;
    simpleworks::marlin::generate_proving_and_verifying_keys(universal_srs, constraint_system)
}

// We are using this function to build a program because in order to do that
// we need inputs.
/// Defaults the inputs for a given function.
pub fn default_user_inputs(function: &Function<Testnet3>) -> Result<Vec<SimpleworksValueType>> {
    let mut default_user_inputs: Vec<SimpleworksValueType> = Vec::new();
    for function_input in function.inputs() {
        let default_user_input = match function_input.value_type() {
            // UInt
            ValueType::Public(PlaintextType::Literal(LiteralType::U8))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U8)) => {
                SimpleworksValueType::U8(u8::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U16))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U16)) => {
                SimpleworksValueType::U16(u16::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U32))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U32)) => {
                SimpleworksValueType::U32(u32::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U64))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U64)) => {
                SimpleworksValueType::U64(u64::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U128))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U128)) => {
                SimpleworksValueType::U128(u128::default())
            }
            // Address
            ValueType::Public(PlaintextType::Literal(LiteralType::Address))
            | ValueType::Private(PlaintextType::Literal(LiteralType::Address)) => {
                SimpleworksValueType::Address(
                    *b"aleo11111111111111111111111111111111111111111111111111111111111",
                )
            }
            // Unsupported Cases
            ValueType::Public(_) | ValueType::Private(_) => bail!("Unsupported type"),
            // Records
            ValueType::Record(_) => SimpleworksValueType::Record {
                owner: *b"aleo11111111111111111111111111111111111111111111111111111111111",
                gates: u64::default(),
                entries: RecordEntriesMap::default(),
            },
            // Constant Types
            ValueType::Constant(_) => bail!("Constant types are not supported"),
            // External Records
            ValueType::ExternalRecord(_) => bail!("ExternalRecord types are not supported"),
        };
        default_user_inputs.push(default_user_input);
    }
    Ok(default_user_inputs)
}

/// This function builds the scaffold of the program variables.
/// We use a hash map for such variables, where the key is the variable name
/// and the value is the variable type.
/// All the values start as None, and will be filled in the next steps.
/// For example, this would be the output of executing this function for
/// credits.aleo's transfer function:
/// ```json
/// {
///     "r0": None,
///     "r0.gates": None,
///     "r0.owner": None,
///     "r1": None,
///     "r2": None,
///     "r3": None,
///     "r4": None,
///     "r5": None,
/// }
/// ```
///
/// # Parameters
/// - `function` - function to be analyzed.
///  
/// # Returns
/// - `IndexMap` with the program variables and its `CircuitIOType` values.
///
pub fn function_variables(function: &Function<Testnet3>) -> SimpleFunctionVariables {
    let mut registers: SimpleFunctionVariables = IndexMap::new();

    let function_inputs: Vec<String> = function
        .inputs()
        .into_iter()
        .map(|i| i.register().to_string())
        .collect();

    let function_outputs: Vec<String> = function
        .outputs()
        .into_iter()
        .map(|o| o.register().to_string())
        .collect();

    function.inputs().into_iter().for_each(|i| {
        registers.insert(i.register().to_string(), None);
    });
    function.instructions().iter().for_each(|i| {
        i.operands().iter().for_each(|o| {
            if !function_outputs.contains(&o.to_string())
                && !function_inputs.contains(&o.to_string())
            {
                registers.insert(o.to_string(), None);
            }
        });
        i.destinations().iter().for_each(|d| {
            if !function_outputs.contains(&d.to_string()) {
                registers.insert(d.to_string(), None);
            }
        });
    });

    for function_output in function_outputs {
        registers.insert(function_output, None);
    }

    registers
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
pub fn circuit_outputs(
    function: &Function<Testnet3>,
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
                    SimpleUInt8(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U8(v.value()?)),
                    SimpleUInt16(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U16(v.value()?)),
                    SimpleUInt32(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U32(v.value()?)),
                    SimpleUInt64(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U64(v.value()?)),
                    SimpleRecord(r) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in
                            primitive_bytes.iter_mut().zip(r.owner.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        XXX::Record("serial_number".to_owned(), "commitment".to_owned(), SimpleworksValueType::Record {
                            owner: primitive_bytes,
                            gates: r.gates.value()?,
                            entries: r.entries,
                        })
                    }
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        XXX::Private("hash".to_owned(), SimpleworksValueType::Address(primitive_bytes))
                    }
                }
            } else {
                match program_variable {
                    SimpleUInt8(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U8(v.value()?)),
                    SimpleUInt16(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U16(v.value()?)),
                    SimpleUInt32(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U32(v.value()?)),
                    SimpleUInt64(v) => XXX::Private("hash".to_owned(), SimpleworksValueType::U64(v.value()?)),
                    SimpleRecord(_) => bail!("Records cannot be public"),
                    SimpleAddress(a) => {
                        let mut primitive_bytes = [0_u8; 63];
                        for (primitive_byte, byte) in primitive_bytes.iter_mut().zip(a.value()?.as_bytes())
                        {
                            *primitive_byte = *byte;
                        }
                        XXX::Private("hash".to_owned(), SimpleworksValueType::Address(primitive_bytes))
                    }
                }
            }
        });
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(circuit_outputs)
}

/// Instantiates the inputs inside the given constraint system.
///
/// # Parameters
/// - `function` - function to be analyzed.
/// - `cs` - Constraint System.
/// - `user_inputs` - user inputs of the function.
/// - `program_variables` - variables of the function.
///  
/// # Returns
/// - If Succeeded return Unit type.
///
/// # Errors
/// Literal 'Mismatched function input type with user input type' when function input type differs from user input type.
/// Literal 'Unsupported type' when user input type is unsupported.
/// Literal 'Constant types are not supported' when the input is a constant.
/// Literal 'ExternalRecord types are not supported' when the input is a External Record.
///
pub fn process_inputs(
    function: &Function<Testnet3>,
    cs: &ConstraintSystemRef<ConstraintF>,
    user_inputs: &[SimpleworksValueType],
    program_variables: &mut SimpleFunctionVariables,
) -> Result<()> {
    for (function_input, user_input) in function.inputs().iter().zip(user_inputs) {
        let register = function_input.register();
        let circuit_input = match (function_input.value_type(), user_input) {
            // Public UInt
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U8)),
                SimpleworksValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U16)),
                SimpleworksValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U32)),
                SimpleworksValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U64)),
                SimpleworksValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Public Address
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::Address)),
                SimpleworksValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Private UInt
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U8)),
                SimpleworksValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U16)),
                SimpleworksValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U32)),
                SimpleworksValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U64)),
                SimpleworksValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Private Address
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::Address)),
                SimpleworksValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Literal Type Error Cases
            (
                ValueType::Private(PlaintextType::Literal(
                    LiteralType::Address
                    | LiteralType::U64
                    | LiteralType::U32
                    | LiteralType::U16
                    | LiteralType::U8,
                ))
                | ValueType::Public(PlaintextType::Literal(
                    LiteralType::Address
                    | LiteralType::U64
                    | LiteralType::U32
                    | LiteralType::U16
                    | LiteralType::U8,
                )),
                _,
            ) => {
                bail!("Mismatched function input type with user input type")
            }
            // Unsupported Cases
            (ValueType::Public(_) | ValueType::Private(_), _) => bail!("Unsupported type"),
            // Records
            (
                ValueType::Record(_),
                SimpleworksValueType::Record {
                    owner: address,
                    gates,
                    entries,
                },
            ) => SimpleRecord(Record {
                owner: AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
                    Ok(address)
                })?,
                gates: UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(gates))?,
                entries: entries.clone(),
            }),
            (ValueType::Record(_), _) => {
                bail!("Mismatched function input type with user input type")
            }
            // Constant Types
            (ValueType::Constant(_), _) => bail!("Constant types are not supported"),
            // External Records
            (ValueType::ExternalRecord(_), _) => bail!("ExternalRecord types are not supported"),
        };
        program_variables.insert(register.to_string(), Some(circuit_input));
    }

    Ok(())
}

/// Executes the given function's instructions, adding the necessary constraints for each one and filling in
/// all the variables in the given `program_variables` index map.
///
/// # Parameters
/// - `function` - function to be analyzed.
/// - `program_variables` - variables of the function.
///  
/// # Returns
/// - If Succeeded return Unit type.
///
/// # Errors
/// Literal 'Error getting the first member of a register member' when an error occurs with the first register element.
/// Literal 'Unsupported record member' When the record member is not an `owner` nor a `gates `.
/// Literal 'Register not assigned in registers' when a register not assigned in the registers.
/// Literal 'Register not found in registers' when a specific register not exists in the registers.
/// Literal 'Literal operands are not supported' when a literal is found in the operands.
/// Literal 'ProgramID operands are not supported' when a ProgramID is found in the operands.
/// Literal 'Caller operands are not supported' when a Caller is found in the operands.
/// Literal 'instruction is not supported currently' when a instruction in the circuit output is not supported.
///
pub fn process_outputs(
    function: &Function<Testnet3>,
    program_variables: &mut SimpleFunctionVariables,
) -> Result<()> {
    for instruction in function.instructions() {
        let mut instruction_operands = Vec::new();
        for operand in instruction.operands() {
            let variable_name = &operand.to_string();
            match (operand, program_variables.get(variable_name)) {
                (Operand::Register(Register::Member(locator, members)), Some(None)) => {
                    if let Some(Some(SimpleRecord(record))) =
                        program_variables.get(&format!("r{locator}"))
                    {
                        match members
                            .get(0)
                            .ok_or("Error getting the first member of a register member")
                            .map_err(|e| anyhow!("{}", e))?
                            .to_string()
                            .as_str()
                        {
                            "owner" => {
                                let owner_operand = SimpleAddress(record.owner.clone());
                                program_variables
                                    .insert(variable_name.to_string(), Some(owner_operand.clone()));
                                instruction_operands.push(owner_operand);
                            }
                            "gates" => {
                                let gates_operand = SimpleUInt64(record.gates.clone());
                                program_variables
                                    .insert(variable_name.to_string(), Some(gates_operand.clone()));
                                instruction_operands.push(gates_operand);
                            }
                            other => bail!("\"{other}\" is an unsupported record member"),
                        };
                    }
                }
                (Operand::Register(_), Some(Some(operand))) => {
                    instruction_operands.push(operand.clone());
                }
                (Operand::Register(r), Some(None)) => {
                    bail!("Register \"{}\" not assigned in registers", r.to_string())
                }
                (Operand::Register(r), None) => {
                    bail!("Register \"{}\" not found in registers", r.to_string())
                }
                (Operand::Literal(_), _) => bail!("Literal operands are not supported"),
                (Operand::ProgramID(_), _) => bail!("ProgramID operands are not supported"),
                (Operand::Caller, _) => bail!("Caller operands are not supported"),
            };
        }

        let circuit_output = match instruction {
            Instruction::Add(_) => instructions::add(&instruction_operands)?,
            Instruction::Cast(_) => instructions::cast(&instruction_operands)?,
            Instruction::Sub(_) => instructions::sub(&instruction_operands)?,
            _ => bail!(
                "{} instruction is not supported currently",
                instruction.opcode()
            ),
        };

        let destination = instruction
            .destinations()
            .get(0)
            .ok_or_else(|| anyhow!("Error getting the destination register"))?
            .to_string();

        program_variables.insert(destination, Some(circuit_output));
    }
    Ok(())
}
