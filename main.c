#include "attack.h"
#include "kyber/ref/indcpa.h"
#include "kyber/ref/params.h"
#include "kyber/ref/polyvec.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t coins[KYBER_SYMBYTES];
  // with this seed we know sk.vec[0].coeffs[0] is -1
  for (size_t i = 0; i < sizeof(coins); i++)
    coins[0] = 69;
  indcpa_keypair_derand(pk, sk, coins);
  polyvec skpv;
  unpack_sk(&skpv, sk);
  pprint_polyvec(&skpv, 1, 1);
  struct indcpa_oracle oracle;
  memcpy(oracle.pk, pk, KYBER_INDCPA_PUBLICKEYBYTES);
  memcpy(oracle.sk, sk, KYBER_INDCPA_SECRETKEYBYTES);

  polyvec recovered_skpv;
  recover_all_secrets(&recovered_skpv, &oracle);
  pprint_polyvec(&recovered_skpv, 0, 1);

  return 0;
}
