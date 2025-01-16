#include <gcrypt.h>
#include <string.h>
#include "bytearray.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/*
prf(ssl_session, &ssl_session->pre_master_secret, "extended master secret",
                     &handshake_hashed_data,
                     NULL, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)

prf(SslDecryptSession *ssl, StringInfo *secret, const char *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, unsigned out_len)

tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                             out, out_len)

tls12_prf(int md, StringInfo* secret, const char* usage,
          StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, unsigned out_len)

tls_hash(secret, &label_seed, md, out, out_len)

tls_hash(StringInfo *secret, StringInfo *seed, int md,
         StringInfo *out, unsigned out_len)

*/


// Pseudo-Random Function (TLS 1.2) 
// label should usually be "key expansion" in our context
// Examples are from TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
int prf(bytearray secret, bytearray s_rand, bytearray c_rand, bytearray out) {
    gcry_md_hd_t    *md;
    gcry_error_t    err;
    const char      *err_str, *err_src;
    bytearray       seed, A, tmp;
    int             len;

    // mac_len, key_len and iv_len are the length of the used ciphers
    // key_len is the 128 in AES_128
    // TODO : Generalize

    int len_needed  = 256*2 + 128*2 + 128*2; 

    // Concatenation of the label and the randoms
    seed.len = 13 + c_rand.len + s_rand.len;
    seed.data = malloc(seed.len);
    memcpy(seed.data, "key expansion", 13);
    memcpy(seed.data+13, s_rand.data, s_rand.len);
    memcpy(seed.data+13+s_rand.len, c_rand.data, c_rand.len);

    // algo is the hashing algorithm that is gonna be used
    // GCRY_MD_SHA384, GCRY_MD_SHA256, GCRY_MD_SM3
    // obtained from the packet ciphersuite last item
    // TODO : Generalize

    err = gcry_md_open(md,GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
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
        err = gcry_md_setkey(*md, secret.data, secret.len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s", err_str, err_src);
            return 1;
        }
        gcry_md_write(*md, A.data, A.len);
        //TODO : Generalize
        A.len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
        memcpy(A.data, gcry_md_read(*md, GCRY_MD_SHA256), A.len);
        gcry_md_reset(*md);

        // HMAC_hash(secret, A(i) + seed)
        err = gcry_md_setkey(*md, secret.data, secret.len);
        if (err != 0) {
            err_str = gcry_strerror(err);
            err_src = gcry_strsource(err);
            printf("prf: gcry_md_setkey failed %s/%s", err_str, err_src);
            return 1;
        }
        gcry_md_write(*md, A.data, A.len);
        gcry_md_write(*md, seed.data, seed.len);
        tmp.len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
        memcpy(tmp.data, gcry_md_read(*md, GCRY_MD_SHA256), tmp.len);
        gcry_md_reset(*md);

        len = MIN(len_needed, tmp.len);
        memcpy(out.data, tmp.data, len);
        out.data += len;
        out.len += len;
        len_needed -= len;
    }

    gcry_md_close(*md);
    out.data -= out.len;

    return 0;
}

int main(int argc, char **argv) {
    // TLS 1.2 : https://datatracker.ietf.org/doc/html/rfc5246#section-6.3
    // Recover MAC_key, key
    // For the AEAD ciphers, also recover IV

    // Requires "SecurityParameters" for length

    bytearray   secret, c_rand, s_rand, out, mac, key, iv;
    int         err;
    
    

    // version = TLS 1.2
    // client_random = f77598b32f033d64c2707a6c1bba1f2658b6fb7b88447ba9b00babe3ce87b1e4
    // server_random = 6788d52f6c61e0c47dadb0e627f6974b7045edf1ea9d9b62444f574e47524401
    // cipher_suite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // packet = 26bc34d7c7b75fccf4ffb4efa4e775a96822778c5727ecb27470bc46059f2d60a4fe38b34cb6fd82690b583bbd83b281f151ac3f887690


    // Here, random is maybe an error, maybe we need both client and server random. From handshake ??
    err = prf(secret, c_rand, s_rand, out);
    if (err != 0) {
        printf("uh oh\n");
        return 1;
    }

    // TODO : Generalize size
    // We découpe toute la donnée qui a été générée pour en extraire les infos

    // *2 because we're only interested in the client ones

    // if "stream" or "CBC" (non-AEAD)
    mac = out.data;
    out += 2*128;

    key = out;
    out += 2*256;

    //if AEAD, need IV
    iv = out;

}
