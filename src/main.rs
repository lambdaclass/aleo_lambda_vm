use anyhow::{anyhow, bail, Result};
use clap::{Arg, ArgAction, Command, Parser, ValueHint};
use simpleworks::types::value::SimpleworksValueType;
use snarkvm::prelude::{Identifier, Parser as AleoParser, Program, Testnet3};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath, required=true)]
    program_path: PathBuf,
    #[clap(value_parser, required = true)]
    function_name: String,
}

fn parse_args() -> Result<(Vec<String>, String, String)> {
    let matches = Command::new("vmtropy")
        .subcommand(
            Command::new("execute")
                // Function to execute.
                .arg(Arg::new("function").required(true))
                // Path of the program.
                .arg(Arg::new("from").required(true))
                // Note: If another argument is to be added, we need to limit the
                // number of inputs with value_terminator.
                // Inputs required for the function (if needed).
                .arg(Arg::new("inputs").num_args(1..).action(ArgAction::Append)),
        )
        .get_matches();

    let (inputs, function_name, program_string) = match matches.subcommand() {
        Some(("execute", execute_cmd)) => {
            let function_name: String = execute_cmd
                .get_one::<String>("function")
                .ok_or_else(|| anyhow!("Error parsing function name parameter"))?
                .to_string();
            let program_string: String = execute_cmd
                .get_one::<String>("from")
                .ok_or_else(|| anyhow!("Error parsing program_string parameter"))?
                .to_string();
            let inputs: Vec<String> = execute_cmd
                .grouped_values_of("inputs")
                .ok_or_else(|| anyhow!("Error parsing input parameters"))?
                .collect::<Vec<Vec<&str>>>()
                .get(0)
                .ok_or_else(|| anyhow!("Error parsing input parameters"))?
                .iter()
                .map(|v| v.to_string())
                .collect();

            (inputs, function_name, program_string)
        }
        _ => bail!("Unsupported command."),
    };

    Ok((inputs, function_name, program_string))
}

fn main() -> Result<()> {
    let (function_inputs, function_name, program_string) = parse_args()?;

    let mut vec_user_inputs = Vec::<SimpleworksValueType>::new();
    for input_value in function_inputs.iter().rev() {
        let v = SimpleworksValueType::try_from(input_value)?;
        vec_user_inputs.push(v);
    }

    execute(&function_name, &program_string, &vec_user_inputs)
}

fn execute(
    function_name: &str,
    program_string: &str,
    user_inputs: &[SimpleworksValueType],
) -> Result<()> {
    println!("Executing function {}...", function_name);

    let program_str = std::fs::read_to_string(program_string).unwrap();

    let (_, program) = Program::<Testnet3>::parse(&program_str).map_err(|e| anyhow!("{}", e))?;

    let function = program
        .get_function(&Identifier::try_from(function_name).map_err(|e| anyhow!("{}", e))?)
        .map_err(|e| anyhow!("{}", e))?;

    let (_verifies, outputs, proof) = vmtropy::execute_function(function, user_inputs)?;

    for (register, value) in outputs {
        println!("Output register {} has value {}", register, value.value()?);
    }

    println!("Proof of execution: \n0x{}", hex::encode(proof));
    Ok(())
}
