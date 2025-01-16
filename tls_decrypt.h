#include <gcrypt.h>

int ssl_cipher_init(
        gcry_cipher_hd_t *cipher,
        int algo,
        unsigned char* sk,
        unsigned char* iv,
        int mode
);
int ssl_cipher_decrypt(
        gcry_cipher_hd_t *cipher,
        unsigned char * out,
        int outl,
        const unsigned char * in,
        int inl
);
int algo_from_str(char *algo_str);
int mode_from_str(char *mode_str);
