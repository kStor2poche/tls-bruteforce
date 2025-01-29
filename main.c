#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <gcrypt.h>
#include <string.h>
#include "log.h"
#include "utils.h"
#include "tls_decrypt.h"
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

    tls_bf_log_init();

    bytearray client_random = hexstr_to_bytearray(argv[1]);
    FILE *key_list_file = fopen(argv[2], "r");
    if (key_list_file == NULL) {
        tls_bf_log(ERROR, "Key list file not found\n");
        exit(2);
    }

    digger *dig = digger_from_file(argv[3]);
    port_list tls_ports = parse_port_list(argv[4]);
    dig_ret res = dig_dig_deep_deep(dig, tls_ports);
    free_port_list(tls_ports);
    if (res != DIG_SUCCESS) {
        tls_bf_log(ERROR, "Information dig failed\n");
        exit(3);
    }
    dug_data data = dig->dug_data;

    tls_bf_log(INFO, "Here's what was dug out");
    tls_bf_logf(INFO, "    TLS version: %04x", data.tls_ver);
    tls_bf_logf(INFO, "    Cipher suite: %04x", data.cipher_suite);
    tls_bf_log_bytearray(INFO, "    Server random", data.server_random);
    tls_bf_logf(INFO, "    1st app actor: %d", data.first_app_actor);
    tls_bf_log_bytearray(INFO, "    1st app data", data.first_app_data);

    int cipher_suite_number = data.cipher_suite;
    SslCipherSuite cipher_suite = get_cipher_suite_by_number(cipher_suite_number);
    int cipher_algo = get_cipher_suite_gcry_algo(&cipher_suite);
    int mode = cipher_suite.mode; // we don't use the gcry one because the following functions use the
                                  // "wireshark" one and proceed to the gcry conversion themselves
    int hash_algo = get_cipher_suite_gcry_digest(&cipher_suite);
    if (mode == -1 || cipher_algo == 0 || hash_algo == -1) {
        tls_bf_log(ERROR, "Extracted cipher suite is unusable (use info logs for more detail)");
        exit(4);
    }


    // BF the keys !
    char cur_key[48*2 + 1];
    while(true) {
        if (fread(&cur_key, sizeof(char), sizeof(cur_key) - 1, key_list_file) != sizeof(cur_key) - 1) {
            puts("Keys exhausted");
            exit(5);
        };
        cur_key[96] = 0;

        bytearray cur_key_bytearray = hexstr_to_bytearray(cur_key);
        tls_bf_log_bytearray(BF_DEBUG, "Current key: ", cur_key_bytearray);

        keyring_material derived;
        if (data.tls_ver == TLSV1DOT2_VERSION) {
            derived = key_derivation_tls12(cipher_algo, hash_algo, cur_key_bytearray, client_random, data.server_random);
        } else if (data.tls_ver == TLSV1DOT3_VERSION) {
            derived = key_derivation_tls13(cipher_algo, hash_algo, &client_random, &data.server_random);
        }
        tls_bf_log_bytearray(BF_DEBUG, "Derived client key", derived.c_key);
        tls_bf_log_bytearray(BF_DEBUG, "Derived client iv", derived.c_iv);
        tls_bf_log_bytearray(BF_DEBUG, "Derived server key", derived.s_key);
        tls_bf_log_bytearray(BF_DEBUG, "Derived server iv", derived.s_iv);

        bytearray key = data.first_app_actor == TLS_CLIENT ? derived.c_key : derived.s_key;
        bytearray iv = data.first_app_actor == TLS_CLIENT ? derived.c_iv : derived.s_iv;
        gcry_cipher_hd_t cipher;
        if (ssl_cipher_init(&cipher, cipher_algo, key.data, iv.data, mode) < 0) {
            tls_bf_log(ERROR, "ssl_cipher failed. See message(s) above for context.");
            exit(6);
        };

        bytearray in = data.first_app_data;
        bytearray *out = &(bytearray){.data = malloc(TCP_MAX_SIZE), .len = TCP_MAX_SIZE};
        if (mode == MODE_GCM ||
            mode == MODE_CCM ||
            mode == MODE_CCM_8 ||
            mode == MODE_POLY1305 ||
            data.tls_ver == TLSV1DOT3_VERSION ||
            data.tls_ver == DTLSV1DOT3_VERSION) {
            if (tls_decrypt_aead_record(&cipher, mode, SSL_ID_APP_DATA, data.tls_ver, iv, in.data, in.len, NULL, 0, out)) {
                break;
            };
        } else {
            // for next tests
            // TODO: to be implemented and tested
            // ssl_cipher_decrypt(&cipher, out, TCP_MAX_SIZE, in.data, in.len);
            puts("Aborting: decryption not yet implemented for non-aead ciphers");
            exit(100);
        }
    }
    fclose(key_list_file);
    printf("Found key %s\n", cur_key);
}
