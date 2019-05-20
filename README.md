# Tania

Intended bug: the chall uses DSA using nonces that are linearly dependent.

Attack: section 4 of [this paper](https://cseweb.ucsd.edu/~mihir/papers/dss-lcg.pdf).

Note: the chall had an unintended bug (which made it easier): to make the reference solution faster (I didn't want to frustrate teams with tons of computation), I intentionally made the nonces smaller, but this unintentionally opened the chall to biased nonces attack.
