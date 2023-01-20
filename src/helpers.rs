use crate::{
    circuit_io_type::{
        SimpleAddress, SimpleBoolean, SimpleField, SimpleRecord, SimpleUInt16, SimpleUInt32,
        SimpleUInt64, SimpleUInt8,
    },
    instructions,
    jaleo::{Identifier, Program, Record as JAleoRecord, RecordEntriesMap, UserInputValueType},
    record::Record as VMRecord,
    CircuitIOType, SimpleFunctionVariables,
};
use anyhow::{anyhow, bail, Result};
use ark_r1cs_std::prelude::{AllocVar, Boolean};
use ark_relations::r1cs::Namespace;
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{
        AddressGadget, ConstraintF, FieldGadget, UInt16Gadget, UInt32Gadget, UInt64Gadget,
        UInt8Gadget,
    },
    marlin::ConstraintSystemRef,
};
use snarkvm::prelude::{
    EntryType, Function, Instruction, Literal, LiteralType, Operand, PlaintextType, Register,
    Testnet3, ValueType,
};

pub fn to_address(primitive_address: String) -> [u8; 63] {
    let mut address = [0_u8; 63];
    for (address_byte, primitive_address_byte) in
        address.iter_mut().zip(primitive_address.as_bytes())
    {
        *address_byte = *primitive_address_byte;
    }
    address
}

pub fn bytes_to_string(bytes: &[u8]) -> Result<String> {
    let mut o = String::with_capacity(63);
    for byte in bytes {
        let c = char::from_u32(<u8 as std::convert::Into<u32>>::into(*byte))
            .ok_or("Error converting u8 into u32")
            .map_err(|e| anyhow!("{e}"))?;
        o.push(c);
    }
    Ok(o)
}

// We are using this function to build a program because in order to do that
// we need inputs.
// NOTE: Default values could make a function not to compile. For example:
// if in some instance of the function there is a subtraction overflow, then
// the function will not compile. We should fix this.
/// Defaults the inputs for a given function.
pub(crate) fn default_user_inputs(
    program: &Program,
    function_name: &Identifier,
) -> Result<Vec<UserInputValueType>> {
    let mut default_user_inputs: Vec<UserInputValueType> = Vec::new();
    for function_input in program.get_function(function_name)?.inputs() {
        let default_user_input = match function_input.value_type() {
            // UInt
            ValueType::Public(PlaintextType::Literal(LiteralType::U8))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U8)) => {
                UserInputValueType::U8(u8::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U16))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U16)) => {
                UserInputValueType::U16(u16::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U32))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U32)) => {
                UserInputValueType::U32(u32::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U64))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U64)) => {
                UserInputValueType::U64(u64::default())
            }
            ValueType::Public(PlaintextType::Literal(LiteralType::U128))
            | ValueType::Private(PlaintextType::Literal(LiteralType::U128)) => {
                UserInputValueType::U128(u128::default())
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
                UserInputValueType::Record(JAleoRecord {
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

pub fn aleo_entries_to_vm_entries(
    aleo_entries: &IndexMap<Identifier, EntryType<Testnet3>>,
) -> Result<RecordEntriesMap> {
    let mut vm_entries = RecordEntriesMap::new();
    for (aleo_entry_identifier, aleo_entry_type) in aleo_entries {
        let vm_entry_type = match aleo_entry_type {
            EntryType::Constant(PlaintextType::Literal(LiteralType::Address))
            | EntryType::Public(PlaintextType::Literal(LiteralType::Address))
            | EntryType::Private(PlaintextType::Literal(LiteralType::Address)) => {
                UserInputValueType::Address(
                    *b"aleo11111111111111111111111111111111111111111111111111111111111",
                )
            }
            EntryType::Constant(PlaintextType::Literal(LiteralType::U8))
            | EntryType::Public(PlaintextType::Literal(LiteralType::U8))
            | EntryType::Private(PlaintextType::Literal(LiteralType::U8)) => {
                UserInputValueType::U8(u8::default())
            }
            EntryType::Constant(PlaintextType::Literal(LiteralType::U16))
            | EntryType::Public(PlaintextType::Literal(LiteralType::U16))
            | EntryType::Private(PlaintextType::Literal(LiteralType::U16)) => {
                UserInputValueType::U16(u16::default())
            }
            EntryType::Constant(PlaintextType::Literal(LiteralType::U32))
            | EntryType::Public(PlaintextType::Literal(LiteralType::U32))
            | EntryType::Private(PlaintextType::Literal(LiteralType::U32)) => {
                UserInputValueType::U32(u32::default())
            }
            EntryType::Constant(PlaintextType::Literal(LiteralType::U64))
            | EntryType::Public(PlaintextType::Literal(LiteralType::U64))
            | EntryType::Private(PlaintextType::Literal(LiteralType::U64)) => {
                UserInputValueType::U64(u64::default())
            }
            EntryType::Constant(PlaintextType::Literal(LiteralType::U128))
            | EntryType::Public(PlaintextType::Literal(LiteralType::U128))
            | EntryType::Private(PlaintextType::Literal(LiteralType::U128)) => {
                UserInputValueType::U128(u128::default())
            }
            EntryType::Constant(PlaintextType::Literal(l))
            | EntryType::Public(PlaintextType::Literal(l))
            | EntryType::Private(PlaintextType::Literal(l)) => bail!(format!(
                "Unsupported literal type {l} for entry {aleo_entry_identifier}"
            )),
            EntryType::Constant(PlaintextType::Interface(_))
            | EntryType::Public(PlaintextType::Interface(_))
            | EntryType::Private(PlaintextType::Interface(_)) => {
                bail!("Interface type is not supported")
            }
        };
        vm_entries.insert(aleo_entry_identifier.to_string(), vm_entry_type);
    }
    Ok(vm_entries)
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
pub fn function_variables(
    function: &Function<Testnet3>,
    constraint_system: ConstraintSystemRef,
) -> Result<SimpleFunctionVariables> {
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
    function.instructions().iter().try_for_each(|i| {
        i.operands().iter().try_for_each(|o| {
            if let Operand::Literal(Literal::U8(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleUInt8(UInt8Gadget::new_constant(
                        constraint_system.clone(),
                        **v,
                    )?)),
                );
            } else if let Operand::Literal(Literal::U16(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleUInt16(UInt16Gadget::new_constant(
                        constraint_system.clone(),
                        **v,
                    )?)),
                );
            } else if let Operand::Literal(Literal::U32(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleUInt32(UInt32Gadget::new_constant(
                        constraint_system.clone(),
                        **v,
                    )?)),
                );
            } else if let Operand::Literal(Literal::U64(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleUInt64(UInt64Gadget::new_constant(
                        constraint_system.clone(),
                        **v,
                    )?)),
                );
            } else if let Operand::Literal(Literal::Address(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleAddress(AddressGadget::new_constant(
                        constraint_system.clone(),
                        to_address(v.to_string()),
                    )?)),
                );
            } else if let Operand::Literal(Literal::Boolean(v)) = o {
                registers.insert(
                    o.to_string(),
                    Some(SimpleBoolean(Boolean::<ConstraintF>::new_constant(
                        constraint_system.clone(),
                        **v,
                    )?)),
                );
            // TODO: Turn a snarkvm_fields::fp_256::Fp256 into an ark_ff::Fp256.
            // } else if let Operand::Literal(Literal::Field(v)) = o {
            //     registers.insert(
            //         o.to_string(),
            //         Some(SimpleField(FieldGadget::new_constant(cs.clone(), **v)?)),
            //     );
            } else if !function_outputs.contains(&o.to_string())
                && !function_inputs.contains(&o.to_string())
            {
                registers.insert(o.to_string(), None);
            }
            Ok::<_, anyhow::Error>(())
        })?;
        i.destinations().iter().for_each(|d| {
            if !function_outputs.contains(&d.to_string()) {
                registers.insert(d.to_string(), None);
            }
        });
        Ok::<_, anyhow::Error>(())
    })?;

    for function_output in function_outputs {
        registers.insert(function_output, None);
    }

    Ok(registers)
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
pub(crate) fn process_inputs(
    function: &Function<Testnet3>,
    cs: &ConstraintSystemRef,
    user_inputs: &[UserInputValueType],
    program_variables: &mut SimpleFunctionVariables,
) -> Result<()> {
    for (function_input, user_input) in function.inputs().iter().zip(user_inputs) {
        let register = function_input.register();
        let circuit_input = match (function_input.value_type(), user_input) {
            // Public UInt
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U8)),
                UserInputValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U16)),
                UserInputValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U32)),
                UserInputValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U64)),
                UserInputValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Public Address
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::Address)),
                UserInputValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Public Field
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::Field)),
                UserInputValueType::Field(f),
            ) => SimpleField(FieldGadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(f),
            )?),
            // Private Boolean
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::Boolean)),
                UserInputValueType::Boolean(b),
            ) => SimpleBoolean(Boolean::<ConstraintF>::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(b),
            )?),
            // Private UInt
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U8)),
                UserInputValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U16)),
                UserInputValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U32)),
                UserInputValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U64)),
                UserInputValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Private Address
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::Address)),
                UserInputValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Private Field
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::Field)),
                UserInputValueType::Field(f),
            ) => SimpleField(FieldGadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(f),
            )?),
            // Private Boolean
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::Boolean)),
                UserInputValueType::Boolean(b),
            ) => SimpleBoolean(Boolean::<ConstraintF>::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(b),
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
            (ValueType::Public(v) | ValueType::Private(v), t) => {
                println!("UNSUPPORTED TYPE: {v:?} {t:?}");
                bail!("Unsupported type")
            }
            // Records
            (
                ValueType::Record(_),
                UserInputValueType::Record(JAleoRecord {
                    owner: address,
                    gates,
                    data,
                    nonce,
                }),
            ) => {
                let mut entries_gadgets: IndexMap<String, CircuitIOType> = IndexMap::new();
                for (k, v) in data {
                    let entry = match v {
                        UserInputValueType::U8(v) => SimpleUInt8(UInt8Gadget::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(v),
                        )?),
                        UserInputValueType::U16(v) => SimpleUInt16(UInt16Gadget::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(v),
                        )?),
                        UserInputValueType::U32(v) => SimpleUInt32(UInt32Gadget::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(v),
                        )?),
                        UserInputValueType::U64(v) => SimpleUInt64(UInt64Gadget::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(v),
                        )?),
                        UserInputValueType::U128(_) => bail!("U128 is not supported"),
                        UserInputValueType::Address(a) => SimpleAddress(
                            AddressGadget::new_witness(Namespace::new(cs.clone(), None), || Ok(a))?,
                        ),
                        UserInputValueType::Record(_) => bail!("Nested records are not supported"),
                        UserInputValueType::Boolean(v) => SimpleBoolean(Boolean::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(v),
                        )?),
                        UserInputValueType::Field(f) => SimpleField(FieldGadget::new_witness(
                            Namespace::new(cs.clone(), None),
                            || Ok(f),
                        )?),
                    };
                    entries_gadgets.insert(k.to_owned(), entry);
                }
                SimpleRecord(VMRecord {
                    owner: AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(address)
                    })?,
                    gates: UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(gates)
                    })?,
                    entries: entries_gadgets,
                    nonce: *nonce,
                })
            }
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
pub(crate) fn process_outputs(
    program: &Program,
    function: &Function<Testnet3>,
    program_variables: &mut SimpleFunctionVariables,
    constraint_system: ConstraintSystemRef,
) -> Result<()> {
    for instruction in function.instructions() {
        let operands = process_operands(instruction.operands(), program_variables)?;
        let circuit_output = match instruction {
            Instruction::Add(_) => instructions::add(&operands)?,
            Instruction::AssertEq(_) => instructions::assert_eq(&operands)?,
            Instruction::AssertNeq(_) => instructions::assert_neq(&operands)?,
            Instruction::And(_) => instructions::and(&operands)?,
            Instruction::Cast(cast) => match cast.register_type() {
                snarkvm::prelude::RegisterType::Record(record_identifier) => {
                    let aleo_record = program.get_record(record_identifier)?;
                    let aleo_record_entries = aleo_record.entries();
                    instructions::cast(
                        instruction.operands(),
                        program_variables,
                        aleo_record_entries,
                        constraint_system.clone(),
                    )?
                }
                _ => bail!("Cast is not supported for non-record types"),
            },
            Instruction::Div(_) => instructions::div(&operands, constraint_system.clone())?,
            Instruction::GreaterThan(_) => instructions::compare(
                &operands,
                constraint_system.clone(),
                instructions::Comparison::GreaterThan,
            )?,
            Instruction::GreaterThanOrEqual(_) => instructions::compare(
                &operands,
                constraint_system.clone(),
                instructions::Comparison::GreaterThanOrEqual,
            )?,
            Instruction::HashPSD2(_) => instructions::hash_psd2(&operands)?,
            Instruction::IsEq(_) => instructions::is_eq(&operands)?,
            Instruction::IsNeq(_) => instructions::is_neq(&operands)?,
            Instruction::LessThan(_) => instructions::compare(
                &operands,
                constraint_system.clone(),
                instructions::Comparison::LessThan,
            )?,
            Instruction::LessThanOrEqual(_) => instructions::compare(
                &operands,
                constraint_system.clone(),
                instructions::Comparison::LessThanOrEqual,
            )?,
            Instruction::Mul(_) => instructions::mul(&operands, constraint_system.clone())?,
            Instruction::Shl(_) => instructions::shl(&operands, constraint_system.clone())?,
            Instruction::Shr(_) => instructions::shr(&operands, constraint_system.clone())?,
            Instruction::Sub(_) => instructions::sub(&operands)?,
            Instruction::Ternary(_) => instructions::ternary(&operands)?,
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

pub fn process_operands(
    operands: &[Operand<Testnet3>],
    program_variables: &mut IndexMap<String, Option<CircuitIOType>>,
) -> Result<IndexMap<String, CircuitIOType>> {
    // instruction_operands is an IndexMap only to keep track of the
    // name of the record entries, so then when casting into records
    // we can know which entry is which.
    let mut instruction_operands: IndexMap<String, CircuitIOType> = IndexMap::new();
    for operand in operands {
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
                            instruction_operands.insert(variable_name.to_owned(), owner_operand);
                        }
                        "gates" => {
                            let gates_operand = SimpleUInt64(record.gates.clone());
                            program_variables
                                .insert(variable_name.to_string(), Some(gates_operand.clone()));
                            instruction_operands.insert(variable_name.to_owned(), gates_operand);
                        }
                        entry => {
                            let entry_operand = record
                                .entries
                                .get(entry)
                                .ok_or(format!("Could not find entry `{entry}` in record entries map. Record entries are {entries:?}", entries = record.entries.keys()))
                                .map_err(|e| anyhow!("{e}"))?
                                .clone();
                            program_variables
                                .insert(variable_name.to_string(), Some(entry_operand.clone()));
                            instruction_operands.insert(entry.to_owned(), entry_operand);
                        }
                    };
                }
            }
            (Operand::Register(_), Some(Some(operand))) => {
                instruction_operands.insert(variable_name.to_owned(), operand.clone());
            }
            (Operand::Register(r), Some(None)) => {
                bail!("Register \"{}\" not assigned in registers", r.to_string())
            }
            (Operand::Register(r), None) => {
                bail!("Register \"{}\" not found in registers", r.to_string())
            }
            (Operand::Literal(Literal::Field(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Field(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Field(*v))
            ),
            (Operand::Literal(Literal::Boolean(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Boolean(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Boolean(*v))
            ),
            (Operand::Literal(Literal::Address(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Address(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Address(*v))
            ),
            (Operand::Literal(Literal::U8(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u8", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U8(v)), Some(None)) => bail!(
                "Literal \"{}\"u8 not assigned in registers",
                Operand::Literal(Literal::U8(*v))
            ),
            (Operand::Literal(Literal::U16(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u16", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U16(v)), Some(None)) => bail!(
                "Literal \"{}\"u16 not assigned in registers",
                Operand::Literal(Literal::U16(*v))
            ),
            (Operand::Literal(Literal::U32(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u32", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U32(v)), Some(None)) => bail!(
                "Literal \"{}\"u32 not assigned in registers",
                Operand::Literal(Literal::U32(*v))
            ),
            (Operand::Literal(Literal::U64(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u64", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U64(v)), Some(None)) => bail!(
                "Literal \"{}\"u64 not assigned in registers",
                Operand::Literal(Literal::U64(*v))
            ),
            (Operand::Literal(_), _) => bail!("Literal operand not supported"),
            (Operand::ProgramID(_), _) => bail!("ProgramID operands are not supported"),
            (Operand::Caller, _) => bail!("Caller operands are not supported"),
        };
    }
    Ok(instruction_operands)
}
