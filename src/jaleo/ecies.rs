use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr as ScalarField, G1Affine as GAffine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_std::UniformRand;
use hkdf::Hkdf;
use sha2::Sha256;

type SecretKey = ScalarField;
type PublicKey = GAffine;

pub type AesKey = [u8; 32];
pub const EMPTY_BYTES: [u8; 0] = [];

fn hkdf_sha256(master: &[u8]) -> Result<AesKey> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&EMPTY_BYTES, &mut out)
        .map_err(|_| anyhow!("Invalid lenght"))?;
    Ok(out)
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let mut rng = ark_std::rand::thread_rng();
    let sk = SecretKey::rand(&mut rng);

    use ark_bls12_381::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
    let g = GAffine::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);

    let pk = g.mul(sk).into_affine();

    (sk, pk)
}

/*
    // #############################################################################
    /// Generate a `(SecretKey, PublicKey)` pair
    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::random(&mut thread_rng());
        (sk, PublicKey::from_secret_key(&sk))
    }

    /// Encrypt a message by a public key
    ///
    /// # Arguments
    ///
    /// * `receiver_pub` - The u8 array reference of a receiver's public key
    /// * `msg` - The u8 array reference of the message to encrypt
    pub fn encrypt(&self, view_key: &Address) -> Result<EncryptedRecord> {
        let receiver_pk = PublicKey::parse_slice(receiver_pub, None)?;
        let (ephemeral_sk, ephemeral_pk) = generate_keypair();

        let aes_key = encapsulate(&ephemeral_sk, &receiver_pk)?;
        let encrypted = aes_encrypt(&aes_key, msg).ok_or(SecpError::InvalidMessage)?;

        let mut cipher_text = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE + encrypted.len());
        cipher_text.extend(ephemeral_pk.serialize().iter());
        cipher_text.extend(encrypted);

        Ok(cipher_text)
    }

    /// Calculate a shared AES key of our secret key and peer's public key by hkdf
    pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<AesKey, SecpError> {
        let mut shared_point = *peer_pk;
        shared_point.tweak_mul_assign(sk)?;

        let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
        master.extend(PublicKey::from_secret_key(sk).serialize().iter());
        master.extend(shared_point.serialize().iter());

        hkdf_sha256(master.as_slice())
    }

    // #############################################################################
*/
