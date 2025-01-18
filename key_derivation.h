#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include "bytearray.h"
typedef struct _keyring_material {
    bytearray key;
    bytearray mac;
    bytearray iv;
} keyring_material;

keyring_material key_derivation();

#endif
