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
    bytearray       seed, A, _A, tmp;
    int             len;

    // allocations 
    // TODO: proper dynamic strings ? Or at least proper sizing ?
    tmp = (bytearray){malloc(TCP_MAX_SIZE), 0};
    A = (bytearray){malloc(TCP_MAX_SIZE), 0};
    _A = (bytearray){malloc(TCP_MAX_SIZE), 0};

    // Concatenation of the label and the randoms
    seed.len = 13 + c_rand->len + s_rand->len;
    seed.data = malloc(seed.len);
    memcpy(seed.data, "key expansion", 13);
    memcpy(seed.data+13, c_rand->data, c_rand->len);
    memcpy(seed.data+13+c_rand->len, s_rand->data, s_rand->len);

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
        len = gcry_md_get_algo_dlen(gcry_md_get_algo(md));
        memcpy(_A.data, gcry_md_read(md, GCRY_MD_SHA256), len);
        A.len = len;
        A.data = _A.data;

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
    bytearray           secret, c_rand, s_rand, out, cmac, smac, ckey, skey, civ, siv;
    int                 key_len, iv_len, mac_len, len_needed;
    unsigned char       *ptr;

    // version = TLS 1.2
    // client_random = fa04f06c223a813f4fb5381b0db7e9ea217c4f86917fa4053dcb10f6185017fa
    // server_random = 67928cc6ced13aae5c205a91da7d825a460df7bdef15ea65444f574e47524401
    // cipher_suite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // packet = 00000000000000017d9db8ea6bf0370f8c45e947047d22d6758c6b6247f059daa9c65147afa19106635c06cdbd4a696f5c7b49b08271a46146aba3f5248545b3
    // master_secret 07a6efff7a2dd8be8e114f2aaca6d448e02ceaf501b5d76c10bd28efffaae3b51d621c64aff5dbd48e4a376a3dc2a99b

    c_rand = hexstr_to_bytearray("fa04f06c223a813f4fb5381b0db7e9ea217c4f86917fa4053dcb10f6185017fa");
    s_rand = hexstr_to_bytearray("67928cc6ced13aae5c205a91da7d825a460df7bdef15ea65444f574e47524401");
    secret = hexstr_to_bytearray("07a6efff7a2dd8be8e114f2aaca6d448e02ceaf501b5d76c10bd28efffaae3b51d621c64aff5dbd48e4a376a3dc2a99b");
    out = (bytearray){malloc(TCP_MAX_SIZE), 0};

    // mac_len, key_len and iv_len are the length of the used ciphers
    // key_len is the 128 in AES_128
    // TODO : Generalize sizes
    key_len = 16;

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
        //cmac = (bytearray){ptr, mac_len};
        //ptr+=mac_len;
        //smac = (bytearray){ptr, mac_len};
        //ptr+=mac_len;
    ckey = (bytearray){ptr, key_len};
    ptr+= key_len;
    skey = (bytearray){ptr, key_len};
    ptr+= key_len;
    
    // if iv_len > 0
        civ = (bytearray){ptr, iv_len};
        ptr += iv_len;
        siv = (bytearray){ptr, iv_len};

    return (keyring_material){ckey, skey, (bytearray){.data=NULL, .len=0}, (bytearray){.data=NULL, .len=0}, civ, siv};
}
