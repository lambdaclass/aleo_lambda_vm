use anyhow::{bail, Result};
use clap::Parser;
use clap::{Arg, ArgAction, Command};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long, value_parser)]
    f: String,
}

fn main() {
    match Args::parse().f.as_str() {
        "test01_add_with_u16_public_inputs" => test01_add_with_u16_public_inputs(),
        "test02_add_with_u16_private_inputs" => test02_add_with_u16_private_inputs(),
        "test03_add_with_u16_private_and_public_inputs" => test03_add_with_u16_private_and_public_inputs(),
        "test04_add_with_u32_public_inputs" => test04_add_with_u32_public_inputs(),
        "test05_add_with_u32_private_inputs" => test05_add_with_u32_private_inputs(),
        "test06_add_with_u32_private_and_public_inputs" => test06_add_with_u32_private_and_public_inputs(),
        "test07_add_with_u64_public_inputs" => test07_add_with_u64_public_inputs(),
        "test08_add_with_u64_private_inputs" => test08_add_with_u64_private_inputs(),
        "test09_add_with_u64_private_and_public_inputs" => test09_add_with_u64_private_and_public_inputs(),
        _ => {}
    }
}

fn read_add_program() -> Result<String> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../programs/add/main.aleo");
    let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
    Ok(program)
}

fn test01_add_with_u16_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(&program_string, "hello_1").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test02_add_with_u16_private_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_2").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test03_add_with_u16_private_and_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_3").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test04_add_with_u32_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_4").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test05_add_with_u32_private_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_5").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test06_add_with_u32_private_and_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_6").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test07_add_with_u64_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_7").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test08_add_with_u64_private_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_8").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}

fn test09_add_with_u64_private_and_public_inputs() {
    let program_string = read_add_program().unwrap();

    // execute circuit
    let (ret_ok, circuit_outputs, _bytes_proof) =
        vmtropy::execute_function(program_string.as_str(), "hello_9").unwrap();
    assert!(ret_ok);

    for (register, output) in circuit_outputs {
        println!("{}: {:?}", register, output.value().unwrap());
    }
}
