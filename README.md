# Key-Recovery Plaintext-Checking Attack on Kyber
Because of the search-decision equivalence of the Learning with Error (LWE) problem (see [Pei16 Section 4.2.2](https://eprint.iacr.org/2015/939.pdf) for details), Kyber/ML-KEM and many other lattice cryptosystems are known to be vulnerable to plaintext-checking attacks (PCA). Even with Fujisaki-Okamoto transformation, timing variability in implementation can be converted into a plaintext-checking oracle and subsequently a devastating side-channel attacks that can recover the entire secret key using only a few thousand traces ([Ueno21](https://eprint.iacr.org/2021/849)).

This project contains some PoC for executing active attacks on Kyber/ML-KEM. For a KR-PCA against the IND-CPA sub-routines, some helper functions can be found in `attack.c` and an example can be found under `tests/sanity.c`:

```c
#include "kyber/ref/randombytes.h"
#include "kyber/ref/indcpa.h"
#include "kyber/ref/polyvec.h"
#include "attack.h"
#include "utils.h"

// generate a random keypair
uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
uint8_t coins[KYBER_SYMBYTES];
randombytes(coins, KYBER_SYMBYTES);
indcpa_keypair_derand(pk, sk, coins);

// keygen will generate the secret polynomial vector in NTT domain. For easy comparison 
// we will need to convert back to standard domain.
polyvec skpv;
unpack_invntt_sk(&skpv, sk);
polyvec_montgomery_reduce(&skpv);

// the oracle have access to the secret key, but will only be used to answer plaintext-
// checking queries
struct indcpa_oracle oracle;
memcpy(oracle.pk, pk, KYBER_INDCPA_PUBLICKEYBYTES);
memcpy(oracle.sk, sk, KYBER_INDCPA_SECRETKEYBYTES);

// the key-recovery attack
polyvec recovered_skpv;
recover_all_secrets(&recovered_skpv, &oracle);
if (polyveccmp(&recovered_skpv, &skpv)) {
    printf("key-recovery succeeded!\n");
}
```

