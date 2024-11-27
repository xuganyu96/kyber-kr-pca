#include "../attack.h"
#include "../kyber/ref/indcpa.h"
#include "../kyber/ref/params.h"
#include "../kyber/ref/randombytes.h"
#include "../utils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NTESTS 100

/**
 * generate a keypair (pk, sk) such that the first coefficient of the first
 * secret polynomial is -1, then craft malformed ciphertext confirming that the
 * decryption behaves as expected
 */
static int probe_single_secret_coefficient(void) {
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t decryption[KYBER_INDCPA_MSGBYTES];
  uint8_t ct[KYBER_INDCPA_BYTES];
  uint8_t coins[KYBER_SYMBYTES];
  // with this seed we know sk.vec[0].coeffs[0] is -1
  for (size_t i = 0; i < sizeof(coins); i++)
    coins[0] = 69;
  indcpa_keypair_derand(pk, sk, coins);

  int16_t malformed_u = 208; // decompress(du=10, compressed_u=(1 << 6))
  int16_t malformed_vs[] = {0,
                            208,
                            416,
                            624,
                            832,            // should be 1
                            1040,           // should be 1
                            1248,           // should be 1
                            1456,           // should be 1
                            1665 - KYBER_Q, // should be 1
                            1873 - KYBER_Q, // should be 1
                            2081 - KYBER_Q, // should be 1
                            2289 - KYBER_Q,
                            2497 - KYBER_Q,
                            2705 - KYBER_Q,
                            2913 - KYBER_Q,
                            3121 - KYBER_Q};
  uint8_t expect_one[] = {0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0};

  for (size_t chosen_v_loc = 0; chosen_v_loc < 16; chosen_v_loc++) {
    polyvec u;
    for (size_t i = 0; i < KYBER_K; i++) {
      for (size_t j = 0; j < KYBER_N; j++) {
        u.vec[i].coeffs[j] = 0;
      }
    }
    u.vec[0].coeffs[0] = malformed_u;
    poly v;
    for (size_t j = 0; j < KYBER_N; j++) {
      v.coeffs[j] = 0;
    }
    v.coeffs[0] = malformed_vs[chosen_v_loc];
    polyvec_compress(ct, &u); // this is "pack_ciphertext in indcpa.c"
    poly_compress(ct + KYBER_POLYVECCOMPRESSEDBYTES, &v);
    indcpa_dec(decryption, ct, sk);
    if (expect_one[chosen_v_loc]) {
      // decryption should be 0x0100...00
      if (decryption[0] != 0x01) {
        printf("missing 1\n");
        return 1;
      }
      for (size_t dec_loc = 1; dec_loc < sizeof(decryption); dec_loc++) {
        if (decryption[dec_loc] != 0) {
          printf("missing 0 in expecting 1\n");
          return 1;
        }
      }
    } else {
      // decryption should be all zeros
      for (size_t dec_loc = 0; dec_loc < sizeof(decryption); dec_loc++) {
        if (decryption[dec_loc] != 0) {
          printf("missing 0\n");
          return 1;
        }
      }
    }
  }

  return 0;
}

/**
 * key-recovery plaintext-checking attack against random IND-CPA key pairs
 */
static int kr_pca(void) {
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t coins[KYBER_SYMBYTES];
  for (int round = 0; round < NTESTS; round++) {
    randombytes(coins, KYBER_SYMBYTES);
    indcpa_keypair_derand(pk, sk, coins);
    polyvec skpv;
    unpack_invntt_sk(&skpv, sk);
    polyvec_montgomery_reduce(&skpv);
    struct indcpa_oracle oracle;
    memcpy(oracle.pk, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    memcpy(oracle.sk, sk, KYBER_INDCPA_SECRETKEYBYTES);

    polyvec recovered_skpv;
    recover_all_secrets(&recovered_skpv, &oracle);

    if (polyveccmp(&recovered_skpv, &skpv)) {
      return 1;
    }
  }

  return 0;
}

int main(void) {
  int fail = 0;

  fail |= probe_single_secret_coefficient();
  fail |= kr_pca();

  if (fail) {
    return 1;
  }

  printf("Ok\n");
  return 0;
}
