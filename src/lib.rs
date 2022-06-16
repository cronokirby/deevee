mod sigma;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

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

    let prover = sigma::OrDLogProver::create(rng, x0, big_x1);
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

    let prover = sigma::OrDLogProver::create(rng, x1, big_x0);
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
