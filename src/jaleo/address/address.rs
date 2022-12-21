pub type Field = ark_ed_on_bls12_377::Fq;
use anyhow::Result;
use snarkvm::prelude::TestRng;

use super::{compute_key::ComputeKey, private_key::PrivateKey, view_key::ViewKey};

static ACCOUNT_SK_SIG_DOMAIN: &str = "AleoAccountSignatureSecretKey0";
static ACCOUNT_R_SIG_DOMAIN: &str = "AleoAccountSignatureRandomizer0";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The underlying address.
    address: u8, // TODO! GroupAffine<Field>,
}

pub fn generate_account() -> Result<(PrivateKey, ViewKey, Address)> {
    // Sample a random private key.
    let private_key = PrivateKey::new(&mut TestRng::default())?;

    // Derive the compute key, view key, and address.
    let compute_key = ComputeKey::try_from(&private_key)?;
    let view_key = ViewKey::try_from(&private_key)?;
    let address = Address::try_from(&compute_key)?;

    // Return the private key and compute key components.
    Ok((private_key, view_key, address))
}

pub fn generate_private_key() -> Result<PrivateKey> {
    PrivateKey::new(&mut TestRng::default())
}

#[cfg(test)]
mod tests {
    use super::generate_private_key;

    #[test]
    fn test_generate_private_key() {
        let ret = generate_private_key().unwrap();

        println!("{:?}", ret);
        assert!(true);
    }

    #[test]
    fn test_generate_account() {
        let account = generate_account().unwrap();

        println!("{:?}", account);
        assert!(true);
    }
}
