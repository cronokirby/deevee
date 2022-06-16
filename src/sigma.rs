use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng};

pub struct DLogProver {
    x: Scalar,
    k: Scalar,
}

impl DLogProver {
    fn create<R: RngCore + CryptoRng>(rng: &mut R, x: Scalar) -> Self {
        todo!()
    }

    fn commit() -> RistrettoPoint {
        todo!()
    }

    fn respond(e: Scalar) -> Scalar {
        todo!()
    }
}
