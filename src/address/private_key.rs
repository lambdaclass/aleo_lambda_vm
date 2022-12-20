use ark_std::rand::{thread_rng, CryptoRng, Rng};

use crate::{field::new_domain_separator, jaleo::Field};

static ACCOUNT_SK_SIG_DOMAIN: &str = "AleoAccountSignatureSecretKey0";
static ACCOUNT_R_SIG_DOMAIN: &str = "AleoAccountSignatureRandomizer0";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    /// The account seed that derives the full private key.
    seed: Field,
    /// The derived signature secret key.
    sk_sig: Field,
    /// The derived signature randomizer.
    r_sig: Field,
}

impl PrivateKey {
    #[inline]
    pub fn new<R: Rng + CryptoRng>(_rng: &mut R) -> Result<Self> {
        // Sample a random account seed.
        let seed = thread_rng().gen();
        Self::try_from(seed)
    }

    pub fn try_from(seed: Field) -> Result<Self> {
        // Construct the sk_sig domain separator.
        let sk_sig_domain = new_domain_separator(ACCOUNT_SK_SIG_DOMAIN)
            .ok_or_else(|| anyhow!("Error in new_domain_separator of sk_sig_domain"))?;

        // Construct the r_sig domain separator.
        let r_sig_input = format!("{}.{}", ACCOUNT_R_SIG_DOMAIN, 0_i32);
        let r_sig_domain = new_domain_separator(&r_sig_input)
            .ok_or_else(|| anyhow!("Error in new_domain_separator of r_sig_domain"))?;

        Ok(Self {
            seed,
            sk_sig: decaf377::Element::hash_to_curve(&sk_sig_domain, &seed)
                .vartime_compress_to_field(),
            r_sig: decaf377::Element::hash_to_curve(&r_sig_domain, &seed)
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
