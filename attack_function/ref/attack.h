#ifndef ATTACKH
#define ATTACKH

#include <stdint.h>
#include "params.h"
#include "randombytes.h"

#define attack_function KYBER_NAMESPACE(attack_function)
void attack_function(uint8_t *sk_bd, uint8_t *pk);

#endif