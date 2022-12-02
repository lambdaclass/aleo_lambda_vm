use anyhow::{anyhow, Result};
use ark_serialize::CanonicalDeserialize;
use simpleworks::marlin::UniversalSRS;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

/// Note: this function will always generate the same universal parameters because
/// the rng seed is hardcoded. This is not going to be the case forever, though, as eventually
/// these parameters will be something generated in a setup ceremony and thus it will not be possible
/// to derive them deterministically like this.
pub fn generate_universal_srs() -> Result<UniversalSRS> {
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

pub fn load_universal_srs_from_file() -> Result<UniversalSRS> {
    let (_parameters_dir, file_dir) = get_universal_srs_dir_and_filepath()?;
    let f = File::open(file_dir)?;
    let reader = BufReader::new(f);
    UniversalSRS::deserialize(reader).map_err(|_e| anyhow!("Error deserializing Universal SRS"))
}
