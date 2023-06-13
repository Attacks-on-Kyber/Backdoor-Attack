#ifndef API_H
#define API_H

#include <stdint.h>
#include "params.h"

#define CRYPTO_SECRETKEYBYTES  2400
#define CRYPTO_PUBLICKEYBYTES  1184
#define CRYPTO_CIPHERTEXTBYTES 1088
#define CRYPTO_BYTES           32

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
