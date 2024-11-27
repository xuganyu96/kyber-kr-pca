#include "attack.h"
#include "kyber/ref/indcpa.h"

/**
 * return 0 if the given ciphertext decrypts to the given plaintext
 */
int pcocmp(const struct indcpa_oracle *oracle, const uint8_t *pt,
           const uint8_t *ct) {
  uint8_t decryption[KYBER_INDCPA_MSGBYTES];
  indcpa_dec(decryption, ct, oracle->sk);

  int diff = 0;
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
    diff |= decryption[i] ^ pt[i];
  }

  return diff;
}

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
                                size_t coeffloc) {
  polyvec u;
  for (int i = 0; i < KYBER_K; i++) {
    for (int j = 0; j < KYBER_N; j++) {
      u.vec[i].coeffs[j] = 0;
    }
  }
  u.vec[polyloc].coeffs[0] = malformed_u;
  poly v;
  for (int j = 0; j < KYBER_N; j++) {
    v.coeffs[j] = 0;
  }
  v.coeffs[coeffloc] = malformed_v;

  polyvec_compress(ct, &u);
  poly_compress(ct + KYBER_POLYVECCOMPRESSEDBYTES, &v);
}

/**
 * Recover a single coefficient using the oracle
 */
int16_t recover_one_secret_coeff(size_t polyloc, size_t coeffloc,
                                 struct indcpa_oracle *oracle) {
  uint8_t malformed_ct[KYBER_INDCPA_BYTES];
  int16_t malformed_u = 208;
  uint8_t all_zero_pt[KYBER_INDCPA_MSGBYTES];
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
    all_zero_pt[i] = 0;
  }

  // TODO: clean up the nested if-else block
  craft_malformed_ciphertext(malformed_ct, malformed_u, 1040, polyloc,
                             coeffloc);
  if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
    // printf("v=1040 decrypts to 0\n");
    craft_malformed_ciphertext(malformed_ct, malformed_u, 1248, polyloc,
                               coeffloc);
    if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
      // printf("v=1248 decrypts to 0\n");
      craft_malformed_ciphertext(malformed_ct, malformed_u, 1456, polyloc,
                                 coeffloc);
      if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
        // printf("v=1456 decrypts to 0\n");
        return 3;
      } else {
        // printf("v=1456 decrypts to 1\n");
        return 2;
      }
    } else {
      // printf("v=1248 decrypts to 1\n");
      return 1;
    }
  } else {
    // printf("v=1040 decrypts to 1\n");
    craft_malformed_ciphertext(malformed_ct, malformed_u, 624, polyloc,
                               coeffloc);
    if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
      // printf("v=624 decrypts to 0\n");
      craft_malformed_ciphertext(malformed_ct, malformed_u, 832, polyloc,
                                 coeffloc);
      if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
        // printf("v=832 decrypts to 0\n");
        return 0;
      } else {
        // printf("v=832 decrypts to 1\n");
        return -1;
      }
    } else {
      // printf("v=624 decrypts to 1\n");
      craft_malformed_ciphertext(malformed_ct, malformed_u, 416, polyloc,
                                 coeffloc);
      if (pcocmp(oracle, all_zero_pt, malformed_ct) == 0) {
        // printf("v=416 decrypts to 0\n");
        return -2;
      } else {
        // printf("v=416 decrypts to 1\n");
        return -3;
      }
    }
  }
}

/**
 * Recover all secret coefficients one at a time and write them to the input
 * polynomial vector
 */
void recover_all_secrets(polyvec *skpv, struct indcpa_oracle *oracle) {
  for (int polyloc = 0; polyloc < KYBER_K; polyloc++) {
    for (int coeffloc = 0; coeffloc < KYBER_N; coeffloc++) {
      skpv->vec[polyloc].coeffs[coeffloc] =
          recover_one_secret_coeff(polyloc, coeffloc, oracle);
    }
  }
}
