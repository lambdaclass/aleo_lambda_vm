use simpleworks::gadgets::ConstraintF;

use super::{compute_key::ComputeKey, private_key::PrivateKey};

/// The account view key used to decrypt records and ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ViewKey(ConstraintF);

//#[cfg(feature = "private_key")]
impl TryFrom<&PrivateKey> for ViewKey {
    type Error = anyhow::Error;

    /// Initializes a new account view key from an account private key.
    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        // Derive the compute key.
        let compute_key = ComputeKey::try_from(private_key)?;
        // Compute view_key := sk_sig + r_sig + sk_prf.
        Ok(Self(
            private_key.sk_sig + &private_key.r_sig + &compute_key.sk_prf,
        ))
    }
}
