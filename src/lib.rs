mod sigma;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
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
