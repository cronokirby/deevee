# Basics

The starting point are Schnorr signatures. Or rather, the Schnorr
sigma protocol for proving knowledge of the discrete logarithm.

The Prover knows an $x$ such that $x \cdot G = X$, and would like to prove
knowledge of $x$ without revealing it. They do this with the following sigma
protocol:

$$
\begin{aligned}
&k \xleftarrow{R} \mathbb{F}_q&\cr
&K \gets k \cdot G&\cr
&&\stackrel{K}{\longrightarrow}&\cr
&&&e \xleftarrow{R} \mathbb{F}_q\cr
&&\stackrel{e}{\longleftarrow}&\cr
&s \gets k - e x&\cr
&&\stackrel{s}{\longrightarrow}&\cr
&&& K \stackrel{?}{=} s \cdot G + e \cdot X\cr
\end{aligned}
$$

Now, this can be turned into a signature scheme
in the usual way, by doing a Fiat-Shamir transform
to replace the random challenge with a deterministic
challenge, by hashing $K$, along with the public key $X$, and a message $m$.
This is how you get Schnorr signatures.

To get designated verifier Schnorr signatures,
instead of proving that you know $x_0$ such that
$x_0 \cdot G = X_0$, you prove that either you know
such an $x_0$, or that you know a $x_1$ such that
$x_1 \cdot G = X_1$, where $X_1$ is the designated verifier.
This will allow the designated verifier to forge
the protocol, since they know the
discrete logarithm of $X_1$.

Thus, we need a way to take the "or" of two sigma protocols,
and apply it to this situation. We can apply
the **CDS-OR** transform for this, as explained in
Protocol 1 of [Improved OR-Composition of Sigma Protocols](https://www.iacr.org/archive/tcc2016a/95620717/95620717.pdf).

Compiled to this specific case, the scheme looks like this:


$$
\begin{aligned}
&s_1, e_1 \xleftarrow{R} \mathbb{F}_q\cr
&K_1 \gets s_1 \cdot G + e_1 \cdot X\cr
&k_0 \xleftarrow{R} \mathbb{F}_q&\cr
&K_0 \gets k_0 \cdot G&\cr
&&\stackrel{K_0, K_1}{\longrightarrow}&\cr
&&&e \xleftarrow{R} \mathbb{F}_q\cr
&&\stackrel{e}{\longleftarrow}&\cr
&e_0 \gets e - e_1\cr
&s_0 \gets k_0 - e_0 x&\cr
&&\stackrel{e_0, e_1, s_0, s_1}{\longrightarrow}&\cr
&&& e_0 + e_1 \stackrel{?}{=} e\cr
&&& K_0 \stackrel{?}{=} s_0 \cdot G + e_0 \cdot X\cr
&&& K_1 \stackrel{?}{=} s_1 \cdot G + e_1 \cdot X\cr
\end{aligned}
$$

Here I've presented the scheme in the case where you know $x_0$,
but naturally the scheme works if you know $x_1$ instead,
just with what calculations you do flipped.

The idea is that "half" of the protocol is the result of
simulating a single Schnorr protocol for the discrete logarithm
you don't know. Because of this, the verifier is convinced
you know one of the two discrete logarithms, but doesn't know which.

# Optimizations

If we naively Fiat-Shamir this, our signature consists
of $(K_0, K_1, e_0, e_1, s_0, s_1)$.

The first observation is that since $e_0 + e_1$ must equal $e$,
we can just send $e_0$, and have the verifier compute
$e_1 \gets e - e_0$.

The second trick is that instead of sending $K_0$ and $K_1$,
we can instead send some value $\hat{e}$ which we claim
to be the output of the Fiat-Shamir challenge. The verifier
can recompute $K_b \gets s_b \cdot G + e_b \cdot X$,
and then check if $H(K_0, K_1, \ldots) \stackrel{?}{=} \hat{e}$.
This is an equivalent scheme, but replaces two points with
an extra scalar.

The end result is a signature:
$$
(\hat{e}, e_0, s_0, s_1)
$$

which consists of just 4 scalars, which is only twice
the size of a Schnorr signature.

# Concrete details

For the curve, I used [Ristretto](https://ristretto.group/ristretto.html).

The natural choice was to use SHA-512 for hashing to create
a scalar.

For the hash, you want to include the public key $X_0$,
the designated verifier $X_1$, along with the commitments $K_0, K_1$,
and finally the message.
One trick I pulled was to include $x_0 \cdot X_1 = x_1 \cdot X_0 = \text{DH}(X_0, X_1)$ inside of the hash. This is the shared secret
between the signer and the verifier. This makes it so that
someone who isn't either the signer or the designated verifier
can't even tell whether or not the signature is valid.
The fact that the designed verifier can forge the signature
should make them not trust it either, but this adds an extra
layer of security as well.
In order to avoid length extension problems, since
the exchange is secret, I calculate the hash as:

$$
\text{SHA-512}(\text{ctx}_A|| X_0 || X_1 || K_0 || K_1 || m) \oplus
\text{SHA-512}(\text{ctx}_B || \text{DH}(X_0, X_1))
$$

Where $\text{ctx}_A$ is the
string `deevee public challenge context 2022-06-16` and
$\text{ctx}_B$ is the string `deevee secret challenge context 2022-06-16`.

By doing two separate hashes, and xoring the results together,
you include both the secret and public derived hashes,
while avoiding any length extension issues stemming from
the fact that the message has a variable length.

Doing an xor is also better than doing a scalar addition, because you avoid
malleability of any kind from that source.
