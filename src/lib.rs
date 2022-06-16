//! This crate provides an implementation of designated verifier signatures.
//! This is like a normal signature scheme, except that the signer also
//! designates a verifier for their signature.
//!
//! Only this verifier can validate the signature. Furthermore, this verifier
//! can't convince anyone else of the validity of the signature, because they
//! can forge signatures which designate them as the verifier.
//!
//! Here's an example which illustrates all of this functionality:
//!
//! ```rust
//! use deevee::*;
//! use rand_core::OsRng;
//!
//! let (privA, pubA) = generate_keypair(&mut OsRng);
//! let (privB, pubB) = generate_keypair(&mut OsRng);
//! let (privC, pubC) = generate_keypair(&mut OsRng);
//!
//! let sig = privA.sign(&mut OsRng, &pubB, b"I like cats");
//! // The signature verifies, because the designee matches
//! assert!(privB.verify(&pubA, b"I like cats", &sig));
//! // If we change the message, verification fails
//! assert!(!privB.verify(&pubA, b"I don't like cats", &sig));
//! // The signer won't verify with a different signer either
//! assert!(!privB.verify(&pubC, b"I like cats", &sig));
//! // The wrong verifier can't validate the signature either
//! assert!(!privC.verify(&pubA, b"I like cats", &sig));
//! // Finally, the verifier can forge a valid signature for themselves
//! let forged = privB.forge(&mut OsRng, &pubA, b"I don't like cats");
//! assert!(privB.verify(&pubA, b"I don't like cats", &forged));
//! ```
mod sigma;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use sigma::OrDLogProver;

const CHALLENGE_PUBLIC_CONTEXT: &'static [u8] = b"deevee public challenge context 2022-06-16";
const CHALLENGE_SECRET_CONTEXT: &'static [u8] = b"deevee secret challenge context 2022-06-16";

/// Generate the challenge for the signature.
///
/// We need the two public points, their secret Diffie-Hellman exchange, and
/// the two nonce commitments.
fn challenge(
    big_x0: &CompressedRistretto,
    big_x1: &CompressedRistretto,
    dh_result: &CompressedRistretto,
    big_k0: &CompressedRistretto,
    big_k1: &CompressedRistretto,
    m: &[u8],
) -> Scalar {
    // The idea is that we hash all of this into a scalar. To avoid length
    // extension attacks we hash the dh_result separately, and then add the two
    // scalars together to get our challenge.

    let mut hasher = Sha512::new_with_prefix(CHALLENGE_PUBLIC_CONTEXT);
    hasher.update(big_x0.as_bytes());
    hasher.update(big_x1.as_bytes());
    hasher.update(big_k0.as_bytes());
    hasher.update(big_k1.as_bytes());
    hasher.update(m);
    let public_challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    let mut hasher = Sha512::new_with_prefix(CHALLENGE_SECRET_CONTEXT);
    hasher.update(dh_result.as_bytes());
    let secret_challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    public_challenge + secret_challenge
}

struct RawSignature {
    e: Scalar,
    e0: Scalar,
    s0: Scalar,
    s1: Scalar,
}

fn raw_sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    x0: &Scalar,
    big_x1: &RistrettoPoint,
    m: &[u8],
) -> RawSignature {
    let big_x0 = x0 * &constants::RISTRETTO_BASEPOINT_TABLE;

    let prover = OrDLogProver::create(rng, x0, big_x1);
    let (big_k0, big_k1) = prover.commit();

    let dh_result = x0 * big_x1;

    let e = challenge(
        &big_x0.compress(),
        &big_x1.compress(),
        &dh_result.compress(),
        &big_k0.compress(),
        &big_k1.compress(),
        m,
    );

    let ((e0, _), (s0, s1)) = prover.respond(&e);

    RawSignature { e, e0, s0, s1 }
}

fn raw_forge<R: RngCore + CryptoRng>(
    rng: &mut R,
    x1: &Scalar,
    big_x0: &RistrettoPoint,
    m: &[u8],
) -> RawSignature {
    let big_x1 = x1 * &constants::RISTRETTO_BASEPOINT_TABLE;

    let prover = OrDLogProver::create(rng, x1, big_x0);
    let (big_k1, big_k0) = prover.commit();

    let dh_result = x1 * big_x0;

    let e = challenge(
        &big_x0.compress(),
        &big_x1.compress(),
        &dh_result.compress(),
        &big_k0.compress(),
        &big_k1.compress(),
        m,
    );

    let ((_, e0), (s1, s0)) = prover.respond(&e);

    RawSignature { e, e0, s0, s1 }
}

fn raw_verify(big_x0: &RistrettoPoint, x1: &Scalar, sig: &RawSignature, m: &[u8]) -> bool {
    let big_x1 = x1 * &constants::RISTRETTO_BASEPOINT_TABLE;
    let dh_result = x1 * big_x0;

    let e1 = sig.e - sig.e0;
    let (big_k0, big_k1) =
        OrDLogProver::recompute((big_x0, &big_x1), (&sig.e0, &e1), (&sig.s0, &sig.s1));
    let e = challenge(
        &big_x0.compress(),
        &big_x1.compress(),
        &dh_result.compress(),
        &big_k0.compress(),
        &big_k1.compress(),
        m,
    );
    e == sig.e
}

/// The length of signatures, in bytes.
const SIGNATURE_LENGTH: usize = 128;

/// Represents a signature designated for a specific verifier.
///
/// Only that verifier can check that this signature is valid, and that verifier
/// can in fact forge valid signatures which designate them as the verifier.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    data: [u8; SIGNATURE_LENGTH],
}

impl Signature {
    fn from_raw(raw: &RawSignature) -> Self {
        let mut data = [0u8; SIGNATURE_LENGTH];
        data[0..32].copy_from_slice(raw.e.as_bytes());
        data[32..64].copy_from_slice(raw.e0.as_bytes());
        data[64..96].copy_from_slice(raw.s0.as_bytes());
        data[96..128].copy_from_slice(raw.s1.as_bytes());

        Self::new(data)
    }

    fn as_raw(&self) -> Option<RawSignature> {
        let e = Scalar::from_canonical_bytes(self.data[0..32].try_into().unwrap())?;
        let e0 = Scalar::from_canonical_bytes(self.data[32..64].try_into().unwrap())?;
        let s0 = Scalar::from_canonical_bytes(self.data[64..96].try_into().unwrap())?;
        let s1 = Scalar::from_canonical_bytes(self.data[96..128].try_into().unwrap())?;

        Some(RawSignature { e, e0, s0, s1 })
    }

    /// Create a Signature from raw bytes.
    pub fn new(data: [u8; SIGNATURE_LENGTH]) -> Self {
        Self { data }
    }

    /// Convert a signature to the raw bytes which make up that signature.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.data
    }
}

/// PublicKey represents an identity.
///
/// This identity is used to represent the person designated to verify a signature,
/// or the person that signed a message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    /// Attempt to create a PublicKey from bytes.
    ///
    /// This can fail if this public key is not valid.
    pub fn from_bytes(data: [u8; 32]) -> Option<Self> {
        Some(Self(CompressedRistretto(data).decompress()?))
    }

    /// Marshall this PublicKey into bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().0
    }
}

/// Represents a private key.
///
/// The private key allows creating designated verifier signatures. These
/// signatures require the private key of that verifier to be validated.
/// Furthermore, the verifier can use their private key to forge valid signatures
/// which designate them.
#[derive(Clone, Copy, PartialEq)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// Attempt to unmarshall bytes into a private key.
    ///
    /// This can fail if the bytes don't represent a valid private key.
    pub fn from_bytes(data: [u8; 32]) -> Option<Self> {
        let scalar = Scalar::from_canonical_bytes(data)?;
        Some(Self(scalar))
    }

    /// Marshall this private key into bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Sign a message, designated to a specific verifier.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        designee: &PublicKey,
        message: &[u8],
    ) -> Signature {
        let raw = raw_sign(rng, &self.0, &designee.0, message);
        Signature::from_raw(&raw)
    }

    /// As a verifier, forge a message from a signer, designated to yourself.
    pub fn forge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        signer: &PublicKey,
        message: &[u8],
    ) -> Signature {
        let raw = raw_forge(rng, &self.0, &signer.0, message);
        Signature::from_raw(&raw)
    }

    /// Verify that a signer's signature on a message is valid.
    ///
    /// You must have been designated the verifier for this to work.
    pub fn verify(&self, signer: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        let raw_sig = match signature.as_raw() {
            None => return false,
            Some(s) => s,
        };
        raw_verify(&signer.0, &self.0, &raw_sig, message)
    }
}

/// Generate a new private key, along with its associated public key.
pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PrivateKey, PublicKey) {
    let scalar = Scalar::random(rng);
    (
        PrivateKey(scalar),
        PublicKey(&scalar * &constants::RISTRETTO_BASEPOINT_TABLE),
    )
}
