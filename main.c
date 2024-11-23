#include "kyber/ref/indcpa.h"
#include "kyber/ref/params.h"
#include "kyber/ref/randombytes.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int uint8ncmp(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
  int diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= lhs[i] ^ rhs[i];
  }
  return diff;
}

int main(void) {
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  indcpa_keypair_derand(pk, sk, coins);

  // if ciphertext is all 0's, then decryption should also be all zeros
  uint8_t ct[KYBER_INDCPA_BYTES];
  for (size_t i = 0; i < sizeof(ct); i++) {
    ct[i] = 0;
  }
  uint8_t pt[KYBER_INDCPA_MSGBYTES];
  for (size_t i = 0; i < sizeof(pt); i++) {
    pt[i] = 0;
  }
  // indcpa_enc(ct, pt, pk, coins);
  uint8_t decryption[KYBER_INDCPA_MSGBYTES];
  indcpa_dec(decryption, ct, sk);

  if (uint8ncmp(decryption, pt, KYBER_INDCPA_MSGBYTES) == 0) {
    printf("decryption is correct!\n");
  } else {
    printf("decryption failed\n");
  }

  printf("Hello, world!\n");
  return 0;
}
