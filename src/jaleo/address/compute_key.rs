use simpleworks::gadgets::ConstraintF;

use crate::g_scalar_multiply;

use super::{private_key::PrivateKey, address::Address};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComputeKey {
    /// The signature public key `pk_sig` := G^sk_sig.
    pub pk_sig: ConstraintF,
    /// The signature public randomizer `pr_sig` := G^r_sig.
    pub pr_sig: ConstraintF,
    /// The PRF secret key `sk_prf` := HashToScalar(pk_sig || pr_sig).
    pub sk_prf: ConstraintF,
}

impl TryFrom<&PrivateKey> for ComputeKey {
    type Error = anyhow::Error;

    /// Derives the account compute key from an account private key.
    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        // Compute pk_sig := G^sk_sig.
        let pk_sig = g_scalar_multiply(&private_key.sk_sig);
        // Compute pr_sig := G^r_sig.
        let pr_sig = g_scalar_multiply(&private_key.r_sig);
        // Compute sk_prf := HashToScalar(pk_sig || pr_sig).
        let sk_prf = hash_to_scalar_psd4(&[pk_sig.to_x_coordinate(), pr_sig.to_x_coordinate()])?;
        // Output the compute key.
        Ok(Self {
            pk_sig,
            pr_sig,
            sk_prf,
        })
    }
}

impl ComputeKey {
    /// Returns the address corresponding to the compute key.
    pub fn to_address(&self) -> Address {
        // Compute pk_prf := G^sk_prf.
        let pk_prf = g_scalar_multiply(&self.sk_prf);
        // Compute the address := pk_sig + pr_sig + pk_prf.
        Address::new(self.pk_sig + self.pr_sig + pk_prf)
    }
}
