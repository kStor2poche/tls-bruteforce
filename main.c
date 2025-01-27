#include <stdint.h>
#include <stdio.h>
#include <gcrypt.h>
#include "tls_decrypt.h"
#include "utils.h"
#include "key_derivation.h"
#include "info_digger.h"

// TODO: use proper buffer sizes or dynamic buffers or sthg idk git gud
#define TCP_MAX_SIZE 65535

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("usage : %s [client random] [key list file] [capture] [comma-separated valid TLS ports]", argv[0]);
        exit(1);
    }

    port_list tls_ports = parse_port_list(argv[4]);

    digger *dig = digger_from_file(argv[3]);

    // TODO: proper call, results, etc
    dig_ret res = dig_dig_deep_deep(dig, tls_ports);

    if (res != DIG_SUCCESS) {
        exit(2);
    }

    dug_data data = dig->dug_data;
    puts("\nDebug: here's what was dug out");
    printf("    TLS version: %04x\n", data.tls_ver);
    printf("    Cipher suite: %04x\n", data.cipher_suite);
    printf("    ");
    print_bytearray(data.server_random);
    printf("    1st app actor: %d\n", data.first_app_actor);
    printf("    ");
    print_bytearray(data.first_app_data);

    int cipher_suite = data.cipher_suite;

    // TODO: parse from cipher suite (WITH gcry_cipher_map_name ???)
    int cipher_algo = GCRY_CIPHER_AES128;
    
    // TODO: parse mode from cipher suite ?
    char *mode_str = "GCM";
    int mode = mode_from_str(mode_str);

    keyring_material test = key_derivation_tls12(GCRY_CIPHER_AES128, GCRY_MD_SHA256, hexstr_to_bytearray("07a6efff7a2dd8be8e114f2aaca6d448e02ceaf501b5d76c10bd28efffaae3b51d621c64aff5dbd48e4a376a3dc2a99b"), hexstr_to_bytearray(argv[1]), data.server_random);

    bytearray packet = data.first_app_data;
    print_bytearray(test.s_key);
    print_bytearray(test.s_iv);

    gcry_cipher_hd_t cipher;
    if (ssl_cipher_init(&cipher, cipher_algo, test.s_key.data, test.s_iv.data, mode) < 0) {
        fputs("ssl_cipher failed. See message(s) above for context.\n", stderr);
        exit(5);
    };

    // for next tests
    // ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, packet.data, packet.len);

    bytearray *out = &(bytearray){.data = malloc(TCP_MAX_SIZE), .len = TCP_MAX_SIZE};
    if (!tls_decrypt_aead_record(&cipher, mode, SSL_ID_APP_DATA, 0x303, test.s_iv, true, packet.data, packet.len, NULL, 0, out)) {
        fputs("failure...\n", stderr);
        exit(6);
    };

    puts("Just cooked the above !");
}
