#include <stdint.h>
#include <stdio.h>
#include <gcrypt.h>
#include "tls_decrypt.h"
#include "bytearray.h"
#include "key_derivation.h"

#define TCP_MAX_SIZE 65535

int main(int argc, char **argv) {
    // for now, we take one key rather than a key list and aim for a "simple" tls decryption
    /*
    if (argc != 6) {
        printf("usage : %s [key (hex)] [iv (hex)] [algo] [mode] [ciphertext]", argv[0]);
        exit(1);
    }

    bytearray key = hexstr_to_bytearray(argv[1]);
    bytearray iv = hexstr_to_bytearray(argv[2]);
    char *cipher_str = argv[3];
    */
    char *cipher_str = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    int cipher_suite = algo_from_str(cipher_str);
    if (cipher_suite == -1) {
        fputs("Unrecognised cipher suite", stderr);
        exit(3);
    }
    
    /*
    char *mode_str = argv[4];
    */
    char *mode_str = "GCM";
    int mode = mode_from_str(mode_str);
    /*
    if (mode == -1) {
        fputs("Unrecognised mode", stderr);
        exit(4);
    }
    const bytearray ciphertext = hexstr_to_bytearray(argv[5]);
    */

    keyring_material test = key_derivation();

    gcry_cipher_hd_t cipher;
    ssl_cipher_init(&cipher, cipher_suite, test.key.data, NULL, mode);

    unsigned char out[TCP_MAX_SIZE]; // max TCP size

    bytearray packet = hexstr_to_bytearray("26bc34d7c7b75fccf4ffb4efa4e775a96822778c5727ecb27470bc46059f2d60a4fe38b34cb6fd82690b583bbd83b281f151ac3f887690");
    ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, packet.data, packet.len);

    printf("Just cooked this, hope it's alright :\n%s\n", out);
}
