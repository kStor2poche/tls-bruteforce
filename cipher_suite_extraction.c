#include "cipher_suite_extraction.h"
#include <gcrypt.h>

/* get digest index */
const int get_cipher_suite_gcry_digest(const SslCipherSuite *cs) {
    return gcry_mds[cs->dig-DIG_MD5];

}

const int get_cipher_suite_g_mode(const SslCipherSuite *cs) {
    printf("cs->modes : %d, ret : %d\n", cs->mode, gcry_modes[cs->mode]);
    return gcry_modes[cs->mode];
}

const int get_cipher_suite_gcry_algo(const SslCipherSuite *cipher_suite) {
    return gcry_cipher_map_name(ciphers[cipher_suite->enc - ENC_START]);
}

/* our code */
const SslCipherSuite get_cipher_suite_by_number(int number) {
    for (int i=0; i<sizeof(cipher_suites)/sizeof(SslCipherSuite); i++) {
        if (cipher_suites[i].number == number) {
            return cipher_suites[i];
        }
    }
    return cipher_suites[sizeof(cipher_suites)/sizeof(SslCipherSuite) - 1]; // <=> NULL
}
