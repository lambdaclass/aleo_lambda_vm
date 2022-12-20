use crate::jaleo::Field;

use super::private_key::PrivateKey;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComputeKey {
    /// The signature public key `pk_sig` := G^sk_sig.
    pk_sig: Field,
    /// The signature public randomizer `pr_sig` := G^r_sig.
    pr_sig: Field,
    /// The PRF secret key `sk_prf` := HashToScalar(pk_sig || pr_sig).
    sk_prf: Field,
}

impl TryFrom<&PrivateKey> for ComputeKey {
    type Error = anyhow::Error;

    /// Derives the account compute key from an account private key.
    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        // Compute pk_sig := G^sk_sig.
        let pk_sig = g_scalar_multiply(private_key.sk_sig);
        // Compute pr_sig := G^r_sig.
        let pr_sig = g_scalar_multiply(private_key.r_sig);
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

fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self> {
    let generator_g = new_bases("AleoAccountEncryptionAndSignatureScheme0");
    generator_g
        .iter()
        .zip_eq(&scalar.to_bits_le())
        .filter_map(|(base, bit)| match bit {
            true => Some(base),
            false => None,
        })
        .sum()
}

fn new_bases(message: &str) -> Vec<Group<Self>> {
    // Hash the given message to a point on the curve, to initialize the starting base.
    let (base, _, _) = Blake2Xs::hash_to_curve::<<Self as Environment>::Affine>(message);

    // Compute the bases up to the size of the scalar field (in bits).
    let mut g = Group::<Self>::new(base);
    let mut g_bases = Vec::with_capacity(Scalar::<Self>::size_in_bits());
    for _ in 0..Scalar::<Self>::size_in_bits() {
        g_bases.push(g);
        g = g.double();
    }
    g_bases
}
