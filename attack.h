/** methods for carrying out attack
 */
#include "kyber/ref/params.h"
#include "kyber/ref/polyvec.h"
#include <stdint.h>
#include <stdio.h>

/** A simple abstraction that simulates a decryption oracle
 */
struct indcpa_oracle {
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
};

/**
 * return 0 if the given ciphertext decrypts to the given plaintext
 */
int pcocmp(const struct indcpa_oracle *oracle, const uint8_t *pt,
           const uint8_t *ct);

/**
 * Kyber.PKE ciphertext contains compressed polynomimal vector `u` and
 * compressed polynomial `v`.
 *
 * This method produces a malformed ciphertext where the polynomial specified by
 * `polyloc` in `u` is a constant `malformed_u` and the coefficient in `v`
 * specified by `coeffloc` is `malformed_v`. Compress `u` and `v`, then write to
 * the input ciphertext buffer.
 */
void craft_malformed_ciphertext(uint8_t *ct, int16_t malformed_u,
                                int16_t malformed_v, size_t polyloc,
                                size_t coeffloc);

/**
 * Recover a single coefficient using the oracle
 */
int16_t recover_one_secret_coeff(size_t polyloc, size_t coeffloc,
                                 struct indcpa_oracle *oracle);

/**
 * Recover all secret coefficients one at a time and write them to the input
 * polynomial vector
 */
void recover_all_secrets(polyvec *skpv, struct indcpa_oracle *oracle);
