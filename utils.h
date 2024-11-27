/** Helper functions
 */
#include "kyber/ref/poly.h"
#include "kyber/ref/polyvec.h"

void pprint_poly(poly *p, uint8_t is_montgomery, uint8_t compact);
void pprint_polyvec(polyvec *pv, uint8_t is_montgomery, uint8_t compact);
void unpack_invntt_sk(polyvec *skpv, const uint8_t *skbytes);
int polyveccmp(polyvec *lhs, polyvec *rhs);
void polyvec_montgomery_reduce(polyvec *pv);
