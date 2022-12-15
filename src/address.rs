use ark_ec::models::twisted_edwards_extended::GroupAffine;
pub type Field = ark_ed_on_bls12_381::Fq;
use anyhow::Result;
use ark_ec::models::bls12::Bls12Parameters;

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
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        // Sample a random account seed.
        Self::try_from(Uniform::rand(rng))
    }

    pub fn try_from(seed: Field) -> Result<Self> {
        // Construct the sk_sig domain separator.
        let sk_sig_domain = Field::new_domain_separator(ACCOUNT_SK_SIG_DOMAIN);

        // Construct the r_sig domain separator.
        let r_sig_input = format!("{}.{}", ACCOUNT_R_SIG_DOMAIN, 0);
        let r_sig_domain = Field::new_domain_separator(&r_sig_input);

        Ok(Self {
            seed,
            sk_sig: N::hash_to_scalar_psd2(&[sk_sig_domain, seed])?,
            r_sig: N::hash_to_scalar_psd2(&[r_sig_domain, seed])?,
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

/// The account view key used to decrypt records and ciphertext.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ViewKey(Field);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The underlying address.
    address: u8, // TODO! GroupAffine<Field>,
}

pub fn generate_account() -> Result<(PrivateKey, ViewKey, Address)> {
    // Sample a random private key.
    let private_key = console::PrivateKey::<CurrentNetwork>::new(&mut TestRng::default())?;

    // Derive the compute key, view key, and address.
    let compute_key = console::ComputeKey::try_from(&private_key)?;
    let view_key = console::ViewKey::try_from(&private_key)?;
    let address = console::Address::try_from(&compute_key)?;

    // Return the private key and compute key components.
    Ok((private_key, view_key, address))
}
