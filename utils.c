#include "utils.h"
#include "kyber/ref/params.h"
#include "kyber/ref/reduce.h"
#include <stdio.h>

// the number of coefficients per row
#define ROWSIZE 32

/**
 * print coefficients of the input polynomial in a grid
 *
 * set is_montgomery to non-zero if coefficients are in Montgomery domain: each
 * will be reduced back to standard form before being printed
 */
void pprint_poly(poly *p, uint8_t is_montgomery, uint8_t compact) {
  for (int coeffloc = 0; coeffloc < KYBER_N; coeffloc++) {
    int16_t coeff = p->coeffs[coeffloc];
    if (is_montgomery)
      coeff = montgomery_reduce(coeff);
    if (compact) {
      printf("%2d", coeff);
    } else {
      printf("%5d", coeff); // 4 digits and a sign
    }
    if (coeffloc % ROWSIZE == ROWSIZE - 1) {
      printf("\n");
    } else {
      printf(",");
    }
  }
}

/**
 * print polynomials in a grid
 */
void pprint_polyvec(polyvec *pv, uint8_t is_montgomery, uint8_t compact) {
  for (int polyloc = 0; polyloc < KYBER_K; polyloc++) {
    printf("polynomial %d:\n", polyloc);
    for (int coeffloc = 0; coeffloc < KYBER_N; coeffloc++) {
      if (coeffloc % ROWSIZE == 0)
        printf("\t");
      int16_t coeff = pv->vec[polyloc].coeffs[coeffloc];
      if (is_montgomery)
        coeff = montgomery_reduce(coeff);
      if (compact) {
        printf("%2d", coeff);
      } else {
        printf("%5d", coeff);
      }
      if (coeffloc % ROWSIZE == ROWSIZE - 1) {
        printf("\n");
      } else {
        printf(",");
      }
    }
  }
}

/** deserialize secret key bytes into the secret polynomial vector
 */
void unpack_invntt_sk(polyvec *skpv, const uint8_t *skbytes) {
  polyvec_frombytes(skpv, skbytes);
  polyvec_invntt_tomont(skpv);
}

/**
 * naively compare two polynomial vectors, return 0 if they are equal
 */
int polyveccmp(polyvec *lhs, polyvec *rhs) {
  int diff = 0;

  for (int polyloc = 0; polyloc < KYBER_K; polyloc++) {
    for (int coeffloc = 0; coeffloc < KYBER_N; coeffloc++) {
      uint16_t lhs_coeff = lhs->vec[polyloc].coeffs[coeffloc];
      uint16_t rhs_coeff = rhs->vec[polyloc].coeffs[coeffloc];
      diff |= lhs_coeff ^ rhs_coeff;
    }
  }

  return diff;
}

/**
 * apply montgomery reduction to all coefficients of the polynomial vector
 * in-place
 */
void polyvec_montgomery_reduce(polyvec *pv) {
  for (int polyloc = 0; polyloc < KYBER_K; polyloc++) {
    for (int coeffloc = 0; coeffloc < KYBER_N; coeffloc++) {
      int16_t coeff = pv->vec[polyloc].coeffs[coeffloc];
      pv->vec[polyloc].coeffs[coeffloc] = montgomery_reduce(coeff);
    }
  }
}
