#include "tls_decrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <gcrypt.h>

int main(int argc, char **argv) {
    if (argc != 6) {
        puts("usage : ssloracle [key (real bytes)] [iv (real bytes)] [algo] [mode] [ciphertext]");
        exit(1);
    }
    uint8_t *key = (uint8_t *)argv[1];
    uint8_t *iv = (uint8_t *)argv[2];
    char *algo_str = argv[3];
    int algo = algo_from_str(algo_str);
    if (algo == -1) {
        exit(3);
    }
    char *mode_str = argv[4];
    int mode = mode_from_str(mode_str);
    if (mode == -1) {
        exit(4);
    }

    gcry_cipher_hd_t *cipher;
    ssl_cipher_init(cipher, algo, key, iv, mode);
}
