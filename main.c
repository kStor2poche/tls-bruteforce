#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <gcrypt.h>
#include <string.h>
#include "tls_decrypt.h"
#include "utils.h"
#include "key_derivation.h"
#include "info_digger.h"
#include "cipher_suite_extraction.h"

// TODO: use proper buffer sizes or dynamic buffers or sthg idk git gud
#define TCP_MAX_SIZE 65535

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("usage : %s [client random] [key list file] [capture] [comma-separated valid TLS ports]\n", argv[0]);
        exit(1);
    }

    bytearray client_random = hexstr_to_bytearray(argv[1]);
    FILE *key_list_file = fopen(argv[2], "rb");
    if (key_list_file == NULL) {
        fputs("Error: key list file not found\n", stderr);
        exit(3);
    }
    digger *dig = digger_from_file(argv[3]);
    port_list tls_ports = parse_port_list(argv[4]);

    dig_ret res = dig_dig_deep_deep(dig, tls_ports);
    if (res != DIG_SUCCESS) {
        fputs("Information dig failed\n", stderr);
        exit(2);
    }
    dug_data data = dig->dug_data;

    // TODO: implement this kind of thing properly, with specific logging functions and retrieve env 1 time only
    //if (secure_getenv("TLS_BF_DEBUG") != NULL) {
    //    puts("\nDebug: here's what was dug out");
    //    printf("    TLS version: %04x\n", data.tls_ver);
    //    printf("    Cipher suite: %04x\n", data.cipher_suite);
    //    printf("    ");
    //    print_bytearray(data.server_random);
    //    printf("    1st app actor: %d\n", data.first_app_actor);
    //    printf("    ");
    //    print_bytearray(data.first_app_data);
    //}

    int cipher_suite_number = data.cipher_suite;
    SslCipherSuite cipher_suite = get_cipher_suite_by_number(cipher_suite_number);
    int cipher_algo = get_cipher_suite_gcry_algo(&cipher_suite);
    int mode = cipher_suite.mode; // we don't use the gcry one because the functions need the
                                  // "wireshark" one and proceed to the gcry conversion themselves
    int hash_algo = get_cipher_suite_gcry_digest(&cipher_suite);
    if (mode == -1 || cipher_algo == 0 || hash_algo == -1) {
        // Identifiers are unusable, fail.
        exit(3);
    }


    // BF the keys !
    char cur_key[48];
    size_t cur_key_len = 0;
    while(true) {
        if (fread(&cur_key, sizeof(uint8_t), sizeof(cur_key), key_list_file) != sizeof(cur_key)) {
            puts("Keys exhausted");
            exit(4);
        }; // yes, we don't care about \n in cur_key

        bytearray cur_key_bytearray = (bytearray){.data=(uint8_t *)cur_key, .len=48};
        keyring_material derived;
        if (data.tls_ver == TLSV1DOT2_VERSION) {
            derived = key_derivation_tls12(cipher_algo, hash_algo, cur_key_bytearray, client_random, data.server_random);
        } else if (data.tls_ver == TLSV1DOT3_VERSION) {
            derived = key_derivation_tls13(cipher_algo, hash_algo, &client_random, &data.server_random);
        }

        bytearray packet = data.first_app_data;
        print_bytearray(derived.s_key);
        print_bytearray(derived.s_iv);

        gcry_cipher_hd_t cipher;
        if (ssl_cipher_init(&cipher, cipher_algo, derived.s_key.data, derived.s_iv.data, mode) < 0) {
            fputs("ssl_cipher failed. See message(s) above for context.\n", stderr);
            exit(5);
        };

        // for next tests
        // ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, packet.data, packet.len);

        bytearray *out = &(bytearray){.data = malloc(TCP_MAX_SIZE), .len = TCP_MAX_SIZE};
        if (tls_decrypt_aead_record(&cipher, mode, SSL_ID_APP_DATA, 0x303, derived.s_iv, false, packet.data, packet.len, NULL, 0, out)) {
            break;
        };
    }
    fclose(key_list_file);
    printf("Found key =");
    for (size_t i = 0; i<48; i++) {
        printf("%02x", cur_key[i]);
    }
    puts("");
}
