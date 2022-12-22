pub type Field = ark_ed_on_bls12_377::Fq;
use anyhow::Result;
use snarkvm::prelude::TestRng;

use super::{compute_key::ComputeKey, private_key::PrivateKey, view_key::ViewKey};

static ACCOUNT_SK_SIG_DOMAIN: &str = "AleoAccountSignatureSecretKey0";
static ACCOUNT_R_SIG_DOMAIN: &str = "AleoAccountSignatureRandomizer0";

use ark_ec::models::bls12::g1::G1Affine;

// TODO: move to a general place
type GroupAffine = G1Affine<ark_bls12_377::Parameters>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    /// The underlying address.
    address: GroupAffine,
}

impl TryFrom<PrivateKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account private key.
    fn try_from(private_key: PrivateKey) -> Result<Self, Self::Error> {
        Self::try_from(&private_key)
    }
}

impl TryFrom<&PrivateKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account private key.
    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        Self::try_from(ComputeKey::try_from(private_key)?)
    }
}

impl TryFrom<ComputeKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account compute key.
    fn try_from(compute_key: ComputeKey) -> Result<Self, Self::Error> {
        Self::try_from(&compute_key)
    }
}

impl TryFrom<&ComputeKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account compute key.
    fn try_from(compute_key: &ComputeKey) -> Result<Self, Self::Error> {
        Ok(compute_key.to_address())
    }
}

impl TryFrom<ViewKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account view key.
    fn try_from(view_key: ViewKey) -> Result<Self, Self::Error> {
        Self::try_from(&view_key)
    }
}

impl TryFrom<&ViewKey> for Address {
    type Error = anyhow::Error;

    /// Derives the account address from an account view key.
    fn try_from(view_key: &ViewKey) -> Result<Self, Self::Error> {
        Ok(view_key.to_address())
    }
}

impl Address {
    pub fn new(group: GroupAffine) -> Self {
        Self { address: group }
    }
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
    use crate::jaleo::address::address::{generate_account, generate_private_key};

    #[test]
    fn test_generate_private_key() {
        let ret = generate_private_key().unwrap();

        println!("{:?}", ret);
    }

    #[test]
    fn test_generate_account() {
        let account = generate_account().unwrap();

        println!("({:?}, {:?}, {:?})", account.0, account.1, account.2);
    }
}
