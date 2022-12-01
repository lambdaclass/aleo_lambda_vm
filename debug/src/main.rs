use anyhow::{bail, Result};
use ark_r1cs_std::R1CSVar;
use clap::Parser as ClapParser;
use clap::{Arg, ArgAction, Command};
use simpleworks::types::value::SimpleworksValueType::{Address, Record, U128, U16, U32, U64};
use snarkvm::prelude::{Identifier, Parser, Program, Testnet3};
use vmtropy::circuit_io_type::SimpleRecord;

#[derive(ClapParser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long, value_parser)]
    f: String,
}

fn main() {
    match Args::parse().f.as_str() {
        "test01_add_with_u16_public_inputs" => test01_add_with_u16_public_inputs(),
        "test02_add_with_u16_private_inputs" => test02_add_with_u16_private_inputs(),
        "test03_add_with_u16_private_and_public_inputs" => {
            test03_add_with_u16_private_and_public_inputs()
        }
        "test04_add_with_u32_public_inputs" => test04_add_with_u32_public_inputs(),
        "test05_add_with_u32_private_inputs" => test05_add_with_u32_private_inputs(),
        "test06_add_with_u32_private_and_public_inputs" => {
            test06_add_with_u32_private_and_public_inputs()
        }
        "test07_add_with_u64_public_inputs" => test07_add_with_u64_public_inputs(),
        "test08_add_with_u64_private_inputs" => test08_add_with_u64_private_inputs(),
        "test09_add_with_u64_private_and_public_inputs" => {
            test09_add_with_u64_private_and_public_inputs()
        }
        "test_subtract_with_u16_public_inputs" => test_subtract_with_u16_public_inputs(),
        "test_subtract_with_u16_private_inputs" => test_subtract_with_u16_private_inputs(),
        "test_subtract_with_u16_private_and_public_inputs" => {
            test_subtract_with_u16_private_and_public_inputs()
        }
        "test_subtract_with_u32_public_inputs" => test_subtract_with_u32_public_inputs(),
        "test_subtract_with_u32_private_inputs" => test_subtract_with_u32_private_inputs(),
        "test_subtract_with_u32_private_and_public_inputs" => {
            test_subtract_with_u32_private_and_public_inputs()
        }
        "test_subtract_with_u64_public_inputs" => test_subtract_with_u64_public_inputs(),
        "test_subtract_with_u64_private_inputs" => test_subtract_with_u64_private_inputs(),
        "test_subtract_with_u64_private_and_public_inputs" => {
            test_subtract_with_u64_private_and_public_inputs()
        }
        "test_record_add" => test_record_add(),
        "test_record_subtract" => test_record_subtract(),
        "test_genesis" => test_genesis(),
        "test_mint" => test_mint(),
        "test_transfer" => test_transfer(),
        "test_combine" => test_combine(),
        "test_split" => test_split(),
        "test_fee" => test_fee(),
        _ => {}
    }
}

fn read_add_program(instruction: &str) -> Result<String> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(&format!("../programs/{instruction}/main.aleo"));
    let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    Ok(program)
}

fn test01_add_with_u16_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_1").unwrap())
        .unwrap();
    /*
    function hello_1:
        input r0 as u16.public;
        input r1 as u16.public;
        add r0 r1 into r2;
        output r2 as u16.public;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test02_add_with_u16_private_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_2").unwrap())
        .unwrap();

    /*
    function hello_2:
        input r0 as u16.private;
        input r1 as u16.private;
        add r0 r1 into r2;
        output r2 as u16.private;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test03_add_with_u16_private_and_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_3").unwrap())
        .unwrap();

    /*
    function hello_3:
        input r0 as u16.public;
        input r1 as u16.public;
        add r0 r1 into r2;
        output r2 as u16.private;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test04_add_with_u32_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_4").unwrap())
        .unwrap();

    /*
    function hello_4:
        input r0 as u32.public;
        input r1 as u32.public;
        add r0 r1 into r2;
        output r2 as u32.public;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test05_add_with_u32_private_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_5").unwrap())
        .unwrap();

    /*
    function hello_5:
        input r0 as u32.private;
        input r1 as u32.private;
        add r0 r1 into r2;
        output r2 as u32.private;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test06_add_with_u32_private_and_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_6").unwrap())
        .unwrap();

    /*
    function hello_6:
        input r0 as u32.public;
        input r1 as u32.public;
        add r0 r1 into r2;
        output r2 as u32.private;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test07_add_with_u64_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_7").unwrap())
        .unwrap();

    /*
    function hello_7:
        input r0 as u64.public;
        input r1 as u64.public;
        add r0 r1 into r2;
        output r2 as u64.public;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test08_add_with_u64_private_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_8").unwrap())
        .unwrap();

    /*
    function hello_8:
        input r0 as u64.private;
        input r1 as u64.private;
        add r0 r1 into r2;
        output r2 as u64.private;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test09_add_with_u64_private_and_public_inputs() {
    let program_string = read_add_program("add").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_9").unwrap())
        .unwrap();

    /*
    function hello_9:
        input r0 as u64.public;
        input r1 as u64.public;
        add r0 r1 into r2;
        output r2 as u64.private;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u16_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_1").unwrap())
        .unwrap();

    /*
    function hello_1:
        input r0 as u16.public;
        input r1 as u16.public;
        add r0 r1 into r2;
        output r2 as u16.public;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u16_private_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_2").unwrap())
        .unwrap();

    /*
    function hello_2:
        input r0 as u16.private;
        input r1 as u16.private;
        add r0 r1 into r2;
        output r2 as u16.private;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u16_private_and_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_3").unwrap())
        .unwrap();

    /*
    function hello_3:
        input r0 as u16.public;
        input r1 as u16.public;
        add r0 r1 into r2;
        output r2 as u16.private;
    */

    let user_inputs = vec![U16(1), U16(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u32_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_4").unwrap())
        .unwrap();

    /*
    function hello_4:
        input r0 as u32.public;
        input r1 as u32.public;
        add r0 r1 into r2;
        output r2 as u32.public;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u32_private_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_5").unwrap())
        .unwrap();

    /*
    function hello_5:
        input r0 as u32.private;
        input r1 as u32.private;
        add r0 r1 into r2;
        output r2 as u32.private;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u32_private_and_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_6").unwrap())
        .unwrap();

    /*
    function hello_6:
        input r0 as u32.public;
        input r1 as u32.public;
        add r0 r1 into r2;
        output r2 as u32.private;
    */

    let user_inputs = vec![U32(1), U32(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u64_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_7").unwrap())
        .unwrap();

    /*
    function hello_7:
        input r0 as u64.public;
        input r1 as u64.public;
        add r0 r1 into r2;
        output r2 as u64.public;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u64_private_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_8").unwrap())
        .unwrap();

    /*
    function hello_8:
        input r0 as u64.private;
        input r1 as u64.private;
        add r0 r1 into r2;
        output r2 as u64.private;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_subtract_with_u64_private_and_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_9").unwrap())
        .unwrap();

    /*
    function hello_9:
        input r0 as u64.public;
        input r1 as u64.public;
        add r0 r1 into r2;
        output r2 as u64.private;
    */

    let user_inputs = vec![U64(1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

#[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
fn test_subtract_with_u128_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_10").unwrap())
        .unwrap();

    /*
    function hello_10:
        input r0 as u128.public;
        input r1 as u128.public;
        add r0 r1 into r2;
        output r2 as u128.public;
    */

    let user_inputs = vec![U128(1), U128(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

#[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
fn test_subtract_with_u128_private_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_11").unwrap())
        .unwrap();

    /*
    function hello_11:
        input r0 as u128.private;
        input r1 as u128.private;
        add r0 r1 into r2;
        output r2 as u128.private;
    */

    let user_inputs = vec![U128(1), U128(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

#[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
fn test_subtract_with_u128_private_and_public_inputs() {
    let program_string = read_add_program("subtract").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_12").unwrap())
        .unwrap();

    /*
    function hello_12:
        input r0 as u128.public;
        input r1 as u128.public;
        add r0 r1 into r2;
        output r2 as u128.private;
    */

    let user_inputs = vec![U128(1), U128(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_record_add() {
    let program_string = read_add_program("record").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_1").unwrap())
        .unwrap();

    let mut address = [0_u8; 63];
    let address_string = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh";
    for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes()) {
        *address_byte = *address_string_byte;
    }

    let user_inputs = vec![Record(address, 0), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test_record_subtract() {
    let program_string = read_add_program("record").unwrap();
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("hello_2").unwrap())
        .unwrap();

    let mut address = [0_u8; 63];
    let address_string = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh";
    for (address_byte, address_string_byte) in address.iter_mut().zip(address_string.as_bytes()) {
        *address_byte = *address_string_byte;
    }

    let user_inputs = vec![Record(address, 1), U64(1)];

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn address(n: u64) -> (String, [u8; 63]) {
    let mut address_bytes = [0_u8; 63];
    let address_string =
        format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
    for (address_byte, address_string_byte) in
        address_bytes.iter_mut().zip(address_string.as_bytes())
    {
        *address_byte = *address_string_byte;
    }
    (address_string, address_bytes)
}

fn test_genesis() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("genesis").unwrap())
        .unwrap();

    let (address_string, address_bytes) = address(0);

    let user_inputs = vec![Address(address_bytes), U64(1)];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    let expected_output_register_locator = &"r2".to_string();
    assert!(constraint_system_is_satisfied);
    assert!(circuit_outputs.len() == 1);
    if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
        assert_eq!(output_register_locator, expected_output_register_locator);
        assert_eq!(record.owner.value().unwrap(), address_string);
        assert_eq!(record.gates.value().unwrap(), 1);
    }
}

fn test_mint() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("mint").unwrap())
        .unwrap();

    let (address_string, address_bytes) = address(0);

    let user_inputs = vec![Address(address_bytes), U64(1)];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    let expected_output_register_locator = &"r2".to_string();
    assert!(constraint_system_is_satisfied);
    assert!(circuit_outputs.len() == 1);
    if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
        assert_eq!(output_register_locator, expected_output_register_locator);
        assert_eq!(record.owner.value().unwrap(), address_string);
        assert_eq!(record.gates.value().unwrap(), 1);
    }
}

fn test_transfer() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("transfer").unwrap())
        .unwrap();

    let (sender_address_string, sender_address_bytes) = address(0);
    let amount_to_transfer = 1_u64;
    let (receiver_address_string, receiver_address_bytes) = address(0);

    let user_inputs = vec![
        Record(sender_address_bytes, amount_to_transfer),
        Address(receiver_address_bytes),
        U64(amount_to_transfer),
    ];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    let receiver_record_output_register = &"r4".to_string();
    let sender_record_output_register = &"r5".to_string();

    assert!(constraint_system_is_satisfied);
    assert_eq!(circuit_outputs.len(), 2);

    let mut circuit_outputs = circuit_outputs.iter();

    // The first output is the resulting record of the receiver.
    if let Some((output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
        assert_eq!(output_register_locator, receiver_record_output_register);
        assert_eq!(
            record.owner.value().unwrap(),
            receiver_address_string,
            "Receiver address is incorrect"
        );
        assert_eq!(
            record.gates.value().unwrap(),
            amount_to_transfer,
            "Receiver amount is incorrect"
        );
    }

    // The second output is the resulting record of the sender.
    if let Some((output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
        assert_eq!(output_register_locator, sender_record_output_register);
        assert_eq!(
            record.owner.value().unwrap(),
            sender_address_string,
            "Sender address is incorrect"
        );
        assert_eq!(
            record.gates.value().unwrap(),
            0,
            "Sender gates is incorrect"
        );
    }
}

fn test_combine() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("combine").unwrap())
        .unwrap();

    let (address_string, address_bytes) = address(0);
    let amount = 1_u64;

    let user_inputs = vec![Record(address_bytes, amount), Record(address_bytes, amount)];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    let expected_output_register_locator = &"r3".to_string();

    assert!(constraint_system_is_satisfied);
    assert_eq!(circuit_outputs.len(), 1);
    if let (output_register_locator, SimpleRecord(record)) = circuit_outputs.first().unwrap() {
        assert_eq!(output_register_locator, expected_output_register_locator);
        assert_eq!(record.owner.value().unwrap(), address_string);
        assert_eq!(record.gates.value().unwrap(), amount * 2);
    }
}

fn test_split() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("split").unwrap())
        .unwrap();

    let (address_string, address_bytes) = address(0);
    let gates_of_existing_record = 2_u64;
    let gates_for_new_record = 1_u64;

    let user_inputs = vec![
        Record(address_bytes, gates_of_existing_record),
        U64(gates_for_new_record),
    ];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    assert!(constraint_system_is_satisfied);
    assert_eq!(circuit_outputs.len(), 2, "Two output records were expected");

    let mut circuit_outputs = circuit_outputs.iter();

    // The first output is new record.
    if let Some((_output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
        assert_eq!(
            record.owner.value().unwrap(),
            address_string,
            "Owner address is incorrect"
        );
        assert_eq!(
            record.gates.value().unwrap(),
            gates_for_new_record,
            "Record amount is incorrect"
        );
    }

    // The second output is the splitted record.
    if let Some((_output_register_locator, SimpleRecord(record))) = circuit_outputs.next() {
        assert_eq!(
            record.owner.value().unwrap(),
            address_string,
            "Owner address is incorrect"
        );
        assert_eq!(
            record.gates.value().unwrap(),
            gates_of_existing_record - gates_for_new_record,
            "Record gates is incorrect"
        );
    }
}

fn test_fee() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/credits.aleo");
    let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    let (_, program) = Program::<Testnet3>::parse(&program_string).unwrap();
    let function = program
        .get_function(&Identifier::try_from("fee").unwrap())
        .unwrap();

    let (address_string, address_bytes) = address(0);
    let amount = 1_u64;
    let fee = 1_u64;

    let user_inputs = vec![Record(address_bytes, amount), U64(fee)];

    let (constraint_system_is_satisfied, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(function, &user_inputs).unwrap();

    assert!(constraint_system_is_satisfied);
    assert_eq!(circuit_outputs.len(), 1, "One output records was expected");

    if let Some((_output_register_locator, SimpleRecord(record))) = circuit_outputs.iter().next() {
        assert_eq!(
            record.owner.value().unwrap(),
            address_string,
            "Owner address is incorrect"
        );
        assert_eq!(
            record.gates.value().unwrap(),
            amount - fee,
            "Record amount is incorrect"
        );
    }
}
