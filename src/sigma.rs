use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// A Sigma protocol for proving knowledge of a discrete logarithm.
///
/// Specifically, this struct holds the state of the prover, and also has
/// an associated method for the verifier.
pub struct DLogProver {
    /// The secret scalar we want to prove that we know.
    x: Scalar,
    /// The random nonce used for this proof.
    k: Scalar,
}

impl DLogProver {
    /// Create an instance of the prover.
    ///
    /// All of the randomness needed is created at this point.
    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, x: Scalar) -> Self {
        let k = Scalar::random(rng);
        Self { x, k }
    }

    /// Calculate the commitment to the nonce.
    ///
    /// This is the first move by the prover in the protocol.
    pub fn commit(&self) -> RistrettoPoint {
        &self.k * &RISTRETTO_BASEPOINT_TABLE
    }

    /// Respond to the challenge sent by the verifier.
    ///
    /// This is the second move by the prover in the protocol.
    pub fn respond(&self, e: &Scalar) -> Scalar {
        self.k - e * self.x
    }

    /// Verify that a prover knows the discrete logarithm of `bigX`.
    ///
    /// Or, at least, verify that this is a valid transcript.
    pub fn verify(
        bigX: &RistrettoPoint,
        bigK: &RistrettoPoint,
        e: &Scalar,
        response: &Scalar,
    ) -> bool {
        bigK == &RistrettoPoint::vartime_double_scalar_mul_basepoint(e, bigX, response)
    }
}
