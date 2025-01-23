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

    int cipher_algo = GCRY_CIPHER_AES128;
    
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

    print_bytearray(test.skey);
    print_bytearray(test.siv);

    gcry_cipher_hd_t cipher;
    if (ssl_cipher_init(&cipher, cipher_algo, test.skey.data, test.siv.data, mode) < 0) {
        fputs("ssl_cipher failed. See message(s) above for context.\n", stderr);
        exit(5);
    };

    bytearray packet = hexstr_to_bytearray("00000000000000017d9db8ea6bf0370f8c45e947047d22d6758c6b6247f059daa9c65147afa19106635c06cdbd4a696f5c7b49b08271a46146aba3f5248545b3");
    // for next tests
    // ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, packet.data, packet.len);

    bytearray *out = &(bytearray){.data = malloc(TCP_MAX_SIZE), .len = TCP_MAX_SIZE};
    if (!tls_decrypt_aead_record(&cipher, mode, SSL_ID_APP_DATA, 0x301, test.siv, true, packet.data, packet.len, NULL, 0, out)) {
        fputs("failure...\n", stderr);
    };

    printf("Just cooked this, hope it's alright :\n%s\n", (char*)out->data);
}
