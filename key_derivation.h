#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include "bytearray.h"
typedef struct _keyring_material {
    bytearray ckey;
    bytearray skey;
    bytearray cmac;
    bytearray smac;
    bytearray civ;
    bytearray siv;
} keyring_material;

keyring_material key_derivation();

#endif
