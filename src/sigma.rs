use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// A sigma protocol for proving knowledge of one of two discrete logarithms.
///
/// The idea is that there's two public points `big_x0`, and `big_x1`, and you
/// want to prove that you know either `x0` such that `x0 * G = big_x0` or
/// `x1` such that `x1 * G = big_x1`.
///
/// In practice this struct, for the prover side, always works as if you know
/// `x0`. To prove the other side, you instead need to swap the arguments and
/// results of the methods.
pub struct OrDLogProver<'a> {
    /// The discrete logarithm we know.
    x0: &'a Scalar,
    /// The random nonce we use.
    k0: Scalar,
    /// We simulate a transcript for the discrete logarithm we don't know.
    fake_big_k1: RistrettoPoint,
    fake_e1: Scalar,
    fake_s1: Scalar,
}

impl <'a> OrDLogProver<'a> {
    /// Create a new instance of the prover.
    ///
    /// We use the discrete logarithm we know, and the point where we don't.
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        x0: &'a Scalar,
        big_x1: &RistrettoPoint,
    ) -> Self {
        let k0 = Scalar::random(rng);
        // Simulate a fake transcript for the discrete logarithm we don't know.
        let fake_e1 = Scalar::random(rng);
        let fake_s1 = Scalar::random(rng);
        let fake_big_k1 =
            RistrettoPoint::vartime_double_scalar_mul_basepoint(&fake_e1, big_x1, &fake_s1);
        Self {
            x0,
            k0,
            fake_big_k1,
            fake_e1,
            fake_s1,
        }
    }

    /// Calculate the commitment, or first message of the sigma protocol.
    ///
    /// The tuple should be flipped if we know the second point instead.
    pub fn commit(&self) -> (RistrettoPoint, RistrettoPoint) {
        let big_k0 = &self.k0 * &RISTRETTO_BASEPOINT_TABLE;
        (big_k0, self.fake_big_k1)
    }

    /// Calculate the response to the challenge.
    ///
    /// The two response tuples should be flipped if we know the second point instead.
    pub fn respond(&self, e: &Scalar) -> ((Scalar, Scalar), (Scalar, Scalar)) {
        let e0 = e - self.fake_e1;
        let s0 = self.k0 - e0 * self.x0;
        ((e0, self.fake_e1), (s0, self.fake_s1))
    }

    /// Recompute the nonce commitments given the response, and the two public points.
    pub fn recompute(
        big_x: (&RistrettoPoint, &RistrettoPoint),
        e: (&Scalar, &Scalar),
        s: (&Scalar, &Scalar),
    ) -> (RistrettoPoint, RistrettoPoint) {
        let big_k0 = RistrettoPoint::vartime_double_scalar_mul_basepoint(e.0, big_x.0, s.0);
        let big_k1 = RistrettoPoint::vartime_double_scalar_mul_basepoint(e.1, big_x.1, s.1);
        (big_k0, big_k1)
    }
}
