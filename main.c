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

    keyring_material test = key_derivation_tls12(GCRY_CIPHER_AES128, GCRY_MD_SHA256, hexstr_to_bytearray("07a6efff7a2dd8be8e114f2aaca6d448e02ceaf501b5d76c10bd28efffaae3b51d621c64aff5dbd48e4a376a3dc2a99b"), hexstr_to_bytearray("fa04f06c223a813f4fb5381b0db7e9ea217c4f86917fa4053dcb10f6185017fa"), hexstr_to_bytearray("67928cc6ced13aae5c205a91da7d825a460df7bdef15ea65444f574e47524401"));

    print_bytearray(test.s_key);
    print_bytearray(test.s_iv);

    gcry_cipher_hd_t cipher;
    if (ssl_cipher_init(&cipher, cipher_algo, test.s_key.data, test.s_iv.data, mode) < 0) {
        fputs("ssl_cipher failed. See message(s) above for context.\n", stderr);
        exit(5);
    };

    bytearray packet = hexstr_to_bytearray("00000000000000017d9db8ea6bf0370f8c45e947047d22d6758c6b6247f059daa9c65147afa19106635c06cdbd4a696f5c7b49b08271a46146aba3f5248545b3");
    // for next tests
    // ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, packet.data, packet.len);

    bytearray *out = &(bytearray){.data = malloc(TCP_MAX_SIZE), .len = TCP_MAX_SIZE};
    if (!tls_decrypt_aead_record(&cipher, mode, SSL_ID_APP_DATA, 0x303, test.s_iv, true, packet.data, packet.len, NULL, 0, out)) {
        fputs("failure...\n", stderr);
        exit(6);
    };

    puts("Just cooked the above !");
}
