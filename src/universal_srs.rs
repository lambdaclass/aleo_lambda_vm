use anyhow::{anyhow, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use log::debug;
use simpleworks::marlin::UniversalSRS;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

/// Note: this function will always generate the same universal parameters because
/// the rng seed is hardcoded. This is not going to be the case forever, though, as eventually
/// these parameters will be something generated in a setup ceremony and thus it will not be possible
/// to derive them deterministically like this.
pub fn generate_universal_srs() -> Result<Box<UniversalSRS>> {
    let rng = &mut simpleworks::marlin::generate_rand();
    simpleworks::marlin::generate_universal_srs(rng)
}

pub fn get_universal_srs_dir_and_filepath() -> Result<(PathBuf, PathBuf)> {
    let parameters_dir = dirs::home_dir()
        .ok_or_else(|| anyhow!("Home dir not found. Set a home directory"))?
        .join(".vmtropy");
    let file_dir = parameters_dir.join("universal_srs");
    Ok((parameters_dir, file_dir))
}

pub fn load_universal_srs_from_file() -> Result<Box<UniversalSRS>> {
    let now = Instant::now();
    let (_parameters_dir, file_dir) = get_universal_srs_dir_and_filepath()?;
    println!("get universal_srs_dir: {}", now.elapsed().as_millis());
    let f = fs::File::open(file_dir)?;
    println!("file_open: {}", now.elapsed().as_millis());
    let reader = BufReader::new(f);
    println!("read: {}", now.elapsed().as_millis());
    Ok(Box::new(UniversalSRS::deserialize(reader).map_err(
        |_e| anyhow!("Error deserializing Universal SRS"),
    )?))
}

pub fn generate_universal_srs_and_write_to_file() -> Result<PathBuf> {
    println!("generating params");
    let now = Instant::now();
    
    let universal_srs = generate_universal_srs()?;
    
    let mut bytes = Vec::new();
    universal_srs.serialize(&mut bytes)?;

    let (parameters_dir, file_dir) = get_universal_srs_dir_and_filepath()?;
    println!("generated params: {}", now.elapsed().as_millis());

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
    println!("saved file: {}", now.elapsed().as_millis());

    Ok(file_dir)
}
