#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

uint8_t buf_in_encrypt[KYBER_SYMBYTES];
uint8_t buf_in_encrypt2[KYBER_SYMBYTES];
uint8_t buf_in_decrypt[KYBER_SYMBYTES];
uint8_t buf_in_decrypt2[KYBER_SYMBYTES];

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  size_t i;
  indcpa_keypair(pk, sk);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);  // m
  // for(int kk = 0; kk < KYBER_SYMBYTES; kk++)
  //   buf[kk] = 0xAA;
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);  // m = H(m)

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);  // m || H(pk)
  hash_g(kr, buf, 2*KYBER_SYMBYTES);  // (K_bar, r)

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  // printf("Encrypt Message: \n");
  // for(int ii = 0; ii < KYBER_SYMBYTES; ii++)
  //   printf("%02x, ", buf[ii]);
  // printf("\n");

  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
    buf_in_encrypt[jj] = buf[jj];

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

int crypto_kem_enc2(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);  // m
  // for(int kk = 0; kk < KYBER_SYMBYTES; kk++)
  //   buf[kk] = 0xAA;
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);  // m = H(m)

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);  // m || H(pk)
  hash_g(kr, buf, 2*KYBER_SYMBYTES);  // (K_bar, r)

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  // printf("Encrypt Message: \n");
  // for(int ii = 0; ii < KYBER_SYMBYTES; ii++)
  //   printf("%02x, ", buf[ii]);
  // printf("\n");

  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
    buf_in_encrypt2[jj] = buf[jj];

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  // printf("Decrypt Message: \n");
  // for(int ii = 0; ii < KYBER_SYMBYTES; ii++)
  //   printf("%02x, ", buf[ii]);
  // printf("\n");

  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
    buf_in_decrypt[jj] = buf[jj];

  /* justify whether m'== m */
  int same_count = 0;
  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
  {
    if(buf_in_decrypt[jj] == buf_in_encrypt[jj])
      same_count = same_count + 1;
    else
    {
      printf("Mismatch: %02x/%02x\n", buf_in_encrypt[jj], buf_in_decrypt[jj]);
    }
  }

  if(same_count == KYBER_SYMBYTES)
  {
    // printf("Success Match of Message...\n");
  }
  else
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX Failure XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc_cmp(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0; 
}

int crypto_kem_dec2(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  // printf("Decrypt Message: \n");
  // for(int ii = 0; ii < KYBER_SYMBYTES; ii++)
  //   printf("%02x, ", buf[ii]);
  // printf("\n");

  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
    buf_in_decrypt2[jj] = buf[jj];

  /* justify whether m'== m */
  int same_count = 0;
  for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
  {
    if(buf_in_decrypt2[jj] == buf_in_encrypt2[jj])
      same_count = same_count + 1;
    else
    {
      printf("Mismatch: %02x/%02x\n", buf_in_encrypt2[jj], buf_in_decrypt2[jj]);
    }
  }

  if(same_count == KYBER_SYMBYTES)
  {
    // printf("Success Match of Message...\n");
  }
  else
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX Failure XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc_cmp(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0; 
}
