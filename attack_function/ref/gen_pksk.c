#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"
#include "math.h"
#include "crypto_kem.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "ecdh.h"
#include "gcm.h" 
#include "klepto_attack.h"
#include "crypto_kem_mceliece460896.h"

uint8_t pk_off[crypto_kem_PUBLICKEYBYTES];
uint8_t sk_off[crypto_kem_SECRETKEYBYTES];

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
    crypto_kem_mceliece460896_ref_keypair(pk_off, sk_off);
    write_key_to_file("../KEYS/publickey.bin", pk_off, sizeof(pk_off));
    write_key_to_file("../KEYS/privatekey.bin", sk_off, sizeof(sk_off));
    return 0;
}
