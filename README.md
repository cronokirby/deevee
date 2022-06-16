# deevee

A crate providing an implementation of [Designated Verifier Signatures (DVS)](https://www.wikiwand.com/en/Designated_verifier_signature).

***This library is experimental Cryptographic Software: use at your own peril.**

<p align="center">
    <img src="./logo.webp" width="40%">
</p>

These are like normal signatures, except that the signer also designates
a special verifier when signing a message. This changes two things about the
resulting signature:

1. The signature can only be verified by that verifier. Other verifiers will see the signature as invalid, and will in fact not even be able to tell whether or not the signature is valid even if they no who the verifier is (so long as they don't know that verifier's private key, or that of the signer).
2. The verifier can forge signatures that designate them. This prevents a verifier from convincing anybody else that the signature is valid, because the verifier could have forged that signature.

This can be useful in situations where you need to sign a piece of data
to convince someone of something, but you want some kind of deniability
about this interaction.

These are essentially a variant of [Schnorr signatures](https://www.wikiwand.com/en/Schnorr_signature), using the [Ristretto curve](https://ristretto.group/ristretto.html).

# Example

Here's an example which illustrates the main APIs of the crate:

```rust
use deevee::*;
use rand_core::OsRng;

let (privA, pubA) = generate_keypair(&mut OsRng);
let (privB, pubB) = generate_keypair(&mut OsRng);
let (privC, pubC) = generate_keypair(&mut OsRng);

let sig = privA.sign(&mut OsRng, &pubB, b"I like cats");
// The signature verifies, because the designee matches
assert!(privB.verify(&pubA, b"I like cats", &sig));
// If we change the message, verification fails
assert!(!privB.verify(&pubA, b"I don't like cats", &sig));
// The signer won't verify with a different signer either
assert!(!privB.verify(&pubC, b"I like cats", &sig));
// The wrong verifier can't validate the signature either
assert!(!privC.verify(&pubA, b"I like cats", &sig));
// Finally, the verifier can forge a valid signature for themselves
let forged = privB.forge(&mut OsRng, &pubA, b"I don't like cats");
assert!(privB.verify(&pubA, b"I don't like cats", &forged));
```

# Details

Further details on the math are available in [math.md](/docs/math.md).
