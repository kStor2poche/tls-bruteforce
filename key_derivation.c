#include <gcrypt.h>
#include <string.h>
#include "bytearray.h"
#include "key_derivation.h"

#define TCP_MAX_SIZE 65535
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Pseudo-Random Function (TLS 1.2) 
// Examples are from TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
static int prf(bytearray *secret, bytearray *s_rand, bytearray *c_rand, bytearray *out, int len_needed) {
    gcry_md_hd_t    md;
    gcry_error_t    err;
    const char      *err_str, *err_src;
    bytearray       seed, A, tmp;
    int             len;

    // allocations 
    // TODO: proper dynamic strings ? Or at least proper sizing ?
    tmp.data = malloc(TCP_MAX_SIZE);
    out->data = malloc(TCP_MAX_SIZE);

    // Concatenation of the label and the randoms
    seed.len = 13 + c_rand->len + s_rand->len;
    seed.data = malloc(seed.len);
    memcpy(seed.data, "key expansion", 13);
    memcpy(seed.data+13, s_rand->data, s_rand->len);
    memcpy(seed.data+13+s_rand->len, c_rand->data, c_rand->len);

    // algo is the hashing algorithm that is gonna be used
    // GCRY_MD_SHA384, GCRY_MD_SHA256, GCRY_MD_SM3
    // obtained from the packet ciphersuite last item
    // TODO : Generalize

    err = gcry_md_open(&md,GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        printf("prf: gcry_md_open failed %s/%s", err_str, err_src);
        return 1;
    }

    // A(0) = seed
    A = seed;
    while (len_needed) {
        // A(i) = HMAC_hash(secret, A(i-1))
        err = gcry_md_setkey(md, secret->data, secret->len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s", err_str, err_src);
            return 1;
        }
        gcry_md_write(md, A.data, A.len);
        //TODO : Generalize
        A.len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
        memcpy(A.data, gcry_md_read(md, GCRY_MD_SHA256), A.len);
        gcry_md_reset(md);

        // HMAC_hash(secret, A(i) + seed)
        err = gcry_md_setkey(md, secret->data, secret->len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s", err_str, err_src);
            return 1;
        }
        gcry_md_write(md, A.data, A.len);
        gcry_md_write(md, seed.data, seed.len);
        tmp.len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
        memcpy(tmp.data, gcry_md_read(md, GCRY_MD_SHA256), tmp.len);
        gcry_md_reset(md);

        len = MIN(len_needed, tmp.len);
        memcpy(out->data, tmp.data, len);
        out->data += len;
        out->len += len;
        len_needed -= len;
    }

    gcry_md_close(md);
    out->data -= out->len;

    return 0;
}

// TLS 1.2 : https://datatracker.ietf.org/doc/html/rfc5246#section-6.3
// Recover MAC_key, key
// For the AEAD ciphers, also recover IV
keyring_material key_derivation() {
    bytearray           secret, c_rand, s_rand, out, mac, key, iv;
    int                 key_len, iv_len, mac_len, err, len_needed;
    unsigned char       *ptr;

    // version = TLS 1.2
    // client_random = f77598b32f033d64c2707a6c1bba1f2658b6fb7b88447ba9b00babe3ce87b1e4
    // server_random = 6788d52f6c61e0c47dadb0e627f6974b7045edf1ea9d9b62444f574e47524401
    // cipher_suite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // packet = 26bc34d7c7b75fccf4ffb4efa4e775a96822778c5727ecb27470bc46059f2d60a4fe38b34cb6fd82690b583bbd83b281f151ac3f887690
    // master_secret 64b207df340f391926f98646089406d15a989daa21c7f6e8df83326f190ae32f93ed91254b6a2cd0bd1bf3aee05c4597

    c_rand = hexstr_to_bytearray("f77598b32f033d64c2707a6c1bba1f2658b6fb7b88447ba9b00babe3ce87b1e4");
    s_rand = hexstr_to_bytearray("6788d52f6c61e0c47dadb0e627f6974b7045edf1ea9d9b62444f574e47524401");
    secret = hexstr_to_bytearray("64b207df340f391926f98646089406d15a989daa21c7f6e8df83326f190ae32f93ed91254b6a2cd0bd1bf3aee05c4597");

    // mac_len, key_len and iv_len are the length of the used ciphers
    // key_len is the 128 in AES_128
    // TODO : Generalize sizes
    key_len = 128;

    // if CBC
        //iv_len = gcry_cipher_get_algo_blklen
    // if GCM || CCM || CCM_8
        iv_len = 4;
    // if POLY1305
        //iv_len = 12

    // MD5=16, SHA1=20, SHA256=32, SHA384=48, SM3=32
    mac_len = 32;

    len_needed  = key_len*2 + iv_len*2 + mac_len*2;

    prf(&secret, &c_rand, &s_rand, &out, len_needed);

    ptr = out.data;

    // if STREAM || CBC
        //mac = (bytearray){ptr, mac_len};
        //ptr+=mac_len*2
    key = (bytearray){ptr, key_len};
    ptr+= key_len*2;
    
    // if iv_len > 0
        iv = (bytearray){ptr, iv_len};

    return (keyring_material){key, mac, iv};
}
