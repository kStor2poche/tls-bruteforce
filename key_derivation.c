#include <gcrypt.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "utils.h"
#include "key_derivation.h"

#define TCP_MAX_SIZE 65535
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Pseudo-Random Function (TLS 1.2) 
// Examples are from TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
static int prf(int algo, bytearray *secret, bytearray *c_rand, bytearray *s_rand, bytearray *out) {
    gcry_md_hd_t    h;
    const unsigned int  h_len = gcry_md_get_algo_dlen(algo);
    gcry_error_t    err;
    const char      *err_str, *err_src;
    bytearray       seed, A, _A, tmp;

    // allocations 
    // TODO : proper size
    tmp = (bytearray){malloc(h_len), h_len};
    A = (bytearray){malloc(TCP_MAX_SIZE), 0};
    _A = (bytearray){malloc(TCP_MAX_SIZE), 0};

    // Concatenation of the label and the randoms
    seed.len = 13 + c_rand->len + s_rand->len;
    seed.data = malloc(seed.len);
    memcpy(seed.data, "key expansion", 13);
    memcpy(seed.data+13, s_rand->data, s_rand->len);
    memcpy(seed.data+13+s_rand->len, c_rand->data, c_rand->len);

    err = gcry_md_open(&h, algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        printf("prf: gcry_md_open failed %s/%s\n", err_str, err_src);
        return -1;
    }

    // A(0) = seed
    A = seed;
    for (size_t offset = 0; offset < out->len; offset += MIN(out->len-offset, h_len)) {
        // A(i) = HMAC_hash(secret, A(i-1))
        err = gcry_md_setkey(h, secret->data, secret->len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s\n", err_str, err_src);
            return -1;
        }
        gcry_md_write(h, A.data, A.len);
        memcpy(_A.data, gcry_md_read(h, algo), h_len);
        A.len = h_len;
        A.data = _A.data;
        gcry_md_reset(h);

        // HMAC_hash(secret, A(i) + seed)
        err = gcry_md_setkey(h, secret->data, secret->len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s\n", err_str, err_src);
            return -1;
        }
        gcry_md_write(h, A.data, A.len);
        gcry_md_write(h, seed.data, seed.len);
        memcpy(tmp.data, gcry_md_read(h, algo), h_len);
        gcry_md_reset(h);

        memcpy(out->data + offset, tmp.data, MIN(out->len-offset, h_len));
    }

    gcry_md_close(h);
    return 0;
}

// TLS 1.2 : https://datatracker.ietf.org/doc/html/rfc5246#section-6.3
keyring_material key_derivation_tls12(int cipher, int hash, bytearray secret, bytearray c_rand, bytearray s_rand) {
    bytearray       out, c_mac, s_mac, c_key, s_key, c_iv, s_iv;
    size_t          mac_len, key_len, iv_len, len_needed;
    unsigned char   *ptr;

    mac_len = gcry_md_get_algo_dlen(hash);
    key_len = gcry_cipher_get_algo_keylen(cipher);

    // if CBC
        //iv_len = gcry_cipher_get_algo_blklen(cipher)
    // if GCM || CCM || CCM_8
        iv_len = 4;
    // if POLY1305
        //iv_len = 12

    len_needed = key_len*2 + iv_len*2 + mac_len*2;
    out = (bytearray){malloc(len_needed), len_needed};

    prf(hash, &secret, &c_rand, &s_rand, &out);

    ptr = out.data;

    // if STREAM || CBC
        //cmac = (bytearray){ptr, mac_len};
        //ptr+=mac_len;
        //smac = (bytearray){ptr, mac_len};
        //ptr+=mac_len;
    // else
        c_mac = (bytearray){.data=NULL, .len=0};
        s_mac = (bytearray){.data=NULL, .len=0};

    c_key = (bytearray){ptr, key_len};
    ptr+= key_len;
    s_key = (bytearray){ptr, key_len};
    ptr+= key_len;
    
    if (iv_len > 0) {
        c_iv = (bytearray){ptr, iv_len};
        ptr += iv_len;
        s_iv = (bytearray){ptr, iv_len};
    } else {
        c_iv = (bytearray){.data=NULL, .len=0};
        s_iv = (bytearray){.data=NULL, .len=0};
    }

    return (keyring_material){c_mac, s_mac, c_key, s_key, c_iv, s_iv};
}

// TLS1.3 https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
// HKDF https://datatracker.ietf.org/doc/html/rfc5869
int hkdf(int algo, bytearray *secret, const bytearray *prefix, bytearray *label, bytearray *out) {
    // TODO : proper size
    bytearray info = (bytearray){malloc(TCP_MAX_SIZE), 0};
    gcry_md_hd_t        h;
    const unsigned int  h_len = gcry_md_get_algo_dlen(algo);
    gcry_error_t        err;
    const char          *err_str, *err_src;
    unsigned char       last[48];

    const uint16_t out_len = htons((uint16_t)out->len);
    memcpy(info.data, (const uint8_t *)&out_len, sizeof(out_len));
    info.len += sizeof(out_len);

    const uint8_t label_len = prefix->len + label->len;
    memcpy(info.data+info.len, &label_len, 1);
    info.len += 1;
    memcpy(info.data+info.len, prefix->data, prefix->len);
    info.len += prefix->len;
    memcpy(info.data+info.len, label->data, label->len);
    info.len += label->len;

    // Empty context
    *(info.data+info.len) = 0;
    info.len += 1;

    err = gcry_md_open(&h, algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        printf("prf: gcry_md_open failed %s/%s\n", err_str, err_src);
        return -1;
    }

    for (size_t offset = 0; offset < out->len; offset += h_len) {
        gcry_md_reset(h);
        gcry_md_setkey(h, secret->data, secret->len);
        if (offset > 0) {
            gcry_md_write(h, last, h_len);
        }
        gcry_md_write(h, info.data, info.len);
        gcry_md_putc(h, (uint8_t) (offset / h_len + 1));

        memcpy(last, gcry_md_read(h, algo), h_len);
        memcpy(out->data + offset, last, MIN(h_len, out->len - offset));
    }

    gcry_md_close(h);
    return 0;
}

keyring_material key_derivation_tls13(int cipher, int hash, bytearray *c_secret, bytearray *s_secret) {
    bytearray c_key = (bytearray){malloc(gcry_cipher_get_algo_keylen(cipher)), gcry_cipher_get_algo_keylen(cipher)};
    bytearray s_key = (bytearray){malloc(gcry_cipher_get_algo_keylen(cipher)), gcry_cipher_get_algo_keylen(cipher)};
    bytearray c_iv = (bytearray){malloc(12), 12};
    bytearray s_iv = (bytearray){malloc(12), 12};

    // if tls13_draft_version < 20
        // const char *prefix = "TLS 1.3, ";
    // else if version == 0xfefc (DTLSv1.3)
        // const char *prefix = "dtls13";
    // else
        const bytearray prefix = {(unsigned char *)"tls13 ", 6};

    hkdf(hash, c_secret, &prefix, &(bytearray){(unsigned char *)"key", 3}, &c_key);
    hkdf(hash, s_secret, &prefix, &(bytearray){(unsigned char *)"key", 3}, &s_key);
    hkdf(hash, c_secret, &prefix, &(bytearray){(unsigned char *)"iv", 2}, &c_iv);
    hkdf(hash, s_secret, &prefix, &(bytearray){(unsigned char *)"iv", 2}, &s_iv);

    // if version == 0xfefc
        // hkdf("sn")

    return (keyring_material){(bytearray){.data=NULL, .len=0}, (bytearray){.data=NULL, .len=0}, c_key, s_key, c_iv, s_iv};
}
