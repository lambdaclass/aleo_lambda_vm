use anyhow::{anyhow, bail, Result};
use ark_serialize::{CanonicalSerialize, Write};
use clap::{Arg, ArgAction, Command, Parser, ValueHint};
use snarkvm::prelude::{Identifier, Parser as AleoParser, Program, Testnet3};
use std::fs;
use std::path::PathBuf;
use vmtropy::generate_universal_srs;
use vmtropy::jaleo::UserInputValueType;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath, required=true)]
    program_path: PathBuf,
    #[clap(value_parser, required = true)]
    function_name: String,
}

fn main() -> Result<()> {
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
        .subcommand(Command::new("generate_parameters"))
        .get_matches();

    match matches.subcommand_name() {
        Some("execute") => {
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
                        .map(|v| (*v).to_string())
                        .collect();

                    (inputs, function_name, program_string)
                }
                _ => bail!("Unsupported command."),
            };

            let mut vec_user_inputs = Vec::<UserInputValueType>::new();
            for input_value in inputs.iter().rev() {
                let v = UserInputValueType::try_from(input_value.clone())?;
                vec_user_inputs.push(v);
            }

            execute(&function_name, &program_string, &vec_user_inputs)
        }
        Some("generate_parameters") => {
            let universal_srs = generate_universal_srs()?;

            let mut bytes = Vec::new();
            universal_srs.serialize(&mut bytes).unwrap();

            let parameters_dir = dirs::home_dir()
                .ok_or_else(|| anyhow!("Home dir not found. Set a home directory"))?
                .join(".vmtropy");
            let file_dir = parameters_dir.join("universal_srs");
            fs::create_dir_all(parameters_dir)?;

            let mut file = std::fs::OpenOptions::new()
                // create or open if it already exists
                .create(true)
                .write(true)
                // Overwrite file, do not append
                .append(false)
                .open(&file_dir)?;

            // This let is so clippy doesn't complain
            let _written_amount = file.write(&bytes)?;

            println!("Stored universal parameters under {file_dir:?}");

            Ok(())
        }
        Some(other_value) => bail!("Unsupported command: {other_value}"),
        None => bail!("No subcommand name given"),
    }
}

fn execute(
    function_name: &str,
    program_string: &str,
    user_inputs: &[UserInputValueType],
) -> Result<()> {
    println!("Executing function {function_name}...");

    // TODO: We need to reverse to do things in the right order. Revisit this.
    let mut inputs_copy = user_inputs.to_vec();
    inputs_copy.reverse();

    let program_str = std::fs::read_to_string(program_string).unwrap();

    let (_, program) = Program::<Testnet3>::parse(&program_str).map_err(|e| anyhow!("{}", e))?;

    let function = program
        .get_function(&Identifier::try_from(function_name).map_err(|e| anyhow!("{}", e))?)
        .map_err(|e| anyhow!("{}", e))?;

    let (_compiled_function_variables, proof) =
        vmtropy::execute_function(&program, &function, &inputs_copy)?;

    for (register, value) in _compiled_function_variables {
        println!(
            "Output register {register} has value {}",
            value.unwrap().value()?
        );
    }

    let mut bytes_proof = Vec::new();
    match proof.serialize(&mut bytes_proof) {
        Ok(_) => println!("Proof of execution: \n0x{}", hex::encode(bytes_proof)),
        Err(_) => println!("⚠️ Error serializing proof"),
    }
    Ok(())
}
