use anyhow::Result;
use clap::{Parser, ValueHint};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath, required=true)]
    program_path: PathBuf,
    #[clap(value_parser, required = true)]
    function_name: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let program_path = args.program_path.to_str().unwrap();
    let program_string = std::fs::read_to_string(program_path)?;

    let function_name = args.function_name;
    println!("Executing function {}...", function_name);
    // TODO Add function inputs as arguments once that's implemented.
    let (_verifies, outputs) = vmtropy::execute_function(&program_string, &function_name)?;

    for (register, value) in outputs {
        println!("Output register {} has value {}", register, value.value()?);
    }

    // TODO: Add proof generation once that's implemented.

    Ok(())
}
