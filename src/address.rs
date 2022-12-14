use ark_ec::models::twisted_edwards_extended::GroupAffine;
pub type Field = ark_ed_on_bls12_381::Fq;
use ark_ec::models::bls12::Bls12Parameters;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    /// The account seed that derives the full private key.
    seed: Field,
    /// The derived signature secret key.
    sk_sig: Field,
    /// The derived signature randomizer.
    r_sig: Field,
}

/// The account view key used to decrypt records and ciphertext.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ViewKey(Field);

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The underlying address.
    address: GroupAffine<dyn Bls12Parameters>,
}
