#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include "utils.h"
typedef struct _keyring_material {
    bytearray c_mac;
    bytearray s_mac;
    bytearray c_key;
    bytearray s_key;
    bytearray c_iv;
    bytearray s_iv;
} keyring_material;

keyring_material key_derivation_tls12(int cipher, int hash, bytearray secret, bytearray c_rand, bytearray s_rand);
keyring_material key_derivation_tls13(int cipher, int hash, bytearray *c_secret, bytearray *s_secret);

#endif
