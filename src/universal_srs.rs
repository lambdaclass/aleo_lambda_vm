use anyhow::{anyhow, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use simpleworks::marlin::UniversalSRS;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;

/// Note: this function will always generate the same universal parameters because
/// the rng seed is hardcoded. This is not going to be the case forever, though, as eventually
/// these parameters will be something generated in a setup ceremony and thus it will not be possible
/// to derive them deterministically like this.
pub fn generate_universal_srs() -> Result<Box<UniversalSRS>> {
    let rng = &mut simpleworks::marlin::generate_rand();
    simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng)
}

pub fn get_universal_srs_dir_and_filepath() -> Result<(PathBuf, PathBuf)> {
    let parameters_dir = dirs::home_dir()
        .ok_or_else(|| anyhow!("Home dir not found. Set a home directory"))?
        .join(".lambdavm");

    let file_dir = parameters_dir.join("universal_srs");
    Ok((parameters_dir, file_dir))
}

pub fn load_universal_srs_from_file() -> Result<Box<UniversalSRS>> {
    let (_parameters_dir, file_dir) = get_universal_srs_dir_and_filepath()?;
    let f = fs::File::open(file_dir)?;
    let reader = BufReader::new(f);
    let des = UniversalSRS::deserialize_unchecked(reader);

    Ok(Box::new(des.map_err(|_e| {
        anyhow!("Error deserializing Universal SRS")
    })?))
}

pub fn generate_universal_srs_and_write_to_file() -> Result<PathBuf> {
    let universal_srs = generate_universal_srs()?;

    let mut bytes = Vec::new();
    universal_srs.serialize_uncompressed(&mut bytes)?;

    let (parameters_dir, file_dir) = get_universal_srs_dir_and_filepath()?;
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

    Ok(file_dir)
}
