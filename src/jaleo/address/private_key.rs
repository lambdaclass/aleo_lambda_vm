use anyhow::{anyhow, Result};
use ark_std::rand::{CryptoRng, Rng};
use simpleworks::{fields::deserialize_field_element, gadgets::ConstraintF};

use crate::field::new_domain_separator;

static ACCOUNT_SK_SIG_DOMAIN: &str = "AleoAccountSignatureSecretKey0";
static ACCOUNT_R_SIG_DOMAIN: &str = "AleoAccountSignatureRandomizer0";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    /// The account seed that derives the full private key.
    pub seed: ConstraintF,
    /// The derived signature secret key.
    pub sk_sig: ConstraintF,
    /// The derived signature randomizer.
    pub r_sig: ConstraintF,
}

impl PrivateKey {
    #[inline]
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        // Sample a random account seed.
        let seed = simpleworks::marlin::generate_rand().gen();
        Self::try_from(seed)
    }

    pub fn try_from(seed: ConstraintF) -> Result<Self> {
        let seed_field = deserialize_field_element(
            hex::decode(seed.as_bytes()).map_err(|_| anyhow!("Error converting element"))?,
        )
        .map_err(|_| anyhow!("Error converting element"))?;

        // Construct the sk_sig domain separator.
        let sk_sig_domain = new_domain_separator(ACCOUNT_SK_SIG_DOMAIN)
            .ok_or_else(|| anyhow!("Error in new_domain_separator of sk_sig_domain"))?;

        // Construct the r_sig domain separator.
        let r_sig_input = format!("{}.0", ACCOUNT_R_SIG_DOMAIN);
        let r_sig_domain = new_domain_separator(&r_sig_input)
            .ok_or_else(|| anyhow!("Error in new_domain_separator of r_sig_domain"))?;
        Ok(Self {
            seed,
            sk_sig: decaf377::Element::hash_to_curve(&sk_sig_domain, &seed_field)
                .vartime_compress_to_field(),
            r_sig: decaf377::Element::hash_to_curve(&r_sig_domain, &seed_field)
                .vartime_compress_to_field(),
        })
    }

    /*
    /// Samples a new random private key.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        // Sample a random account seed.
        Self::try_from(Uniform::rand(rng))
    }
    */
}
