/* contains adapted code from wireshark's epan/dissectors/packet-tls-utils.c
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (c) 2014, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tls_decrypt.h"
#include "log.h"
#include "utils.h"
#include <stdio.h>
#include <stdint.h>
#include <gcrypt.h>
#include <string.h>
#include <stdbool.h>

int ssl_cipher_init(
        gcry_cipher_hd_t *cipher,
        int algo,
        unsigned char* sk,
        unsigned char* iv,
        int mode
) {
    int gcry_modes[] = {
        GCRY_CIPHER_MODE_STREAM,
        GCRY_CIPHER_MODE_CBC,
        GCRY_CIPHER_MODE_GCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_POLY1305,
        GCRY_CIPHER_MODE_ECB, /* used for DTLSv1.3 seq number encryption */
    };
    int err;
    if (algo == -1) {
        /* NULL mode */
        *(cipher) = (gcry_cipher_hd_t)-1;
        return 0;
    }
    err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
    if (err !=0) {
        tls_bf_logf(ERROR, "%s: %s", gcry_strsource(err), gcry_strerror(err));
        return  -1;
    }
    err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
    if (err != 0) {
        tls_bf_logf(ERROR, "%s: %s", gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    /* AEAD cipher suites will set the nonce later. */
    if (mode == MODE_CBC) {
        err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
        if (err != 0) {
            tls_bf_logf(ERROR, "%s: %s", gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
    }
    return 0;
}

inline int ssl_cipher_decrypt(
        gcry_cipher_hd_t *cipher,
        unsigned char * out,
        int outl,
        const unsigned char * in,
        int inl
) {
    if ((*cipher) == (gcry_cipher_hd_t)-1)
    {
        if (in && inl)
            memcpy(out, in, outl < inl ? outl : inl);
        return 0;
    }
    return gcry_cipher_decrypt (*(cipher), out, outl, in, inl);
}

// SslDecoder stub for testing purposes
typedef struct _SslDecoder {
    gcry_cipher_hd_t evp;
    uint64_t seq;
    uint16_t epoch;
} SslDecoder;

// Decrypt records for an aead cipher.
// TODO: cleanup and implement missing ciphers/whatevers
// TODO: use bytearrays as io
bool tls_decrypt_aead_record(
        gcry_cipher_hd_t *cipher,
        ssl_cipher_mode_t mode,
        uint8_t ct, uint16_t record_version,
        bytearray iv,
        const unsigned char *in, uint16_t inl,
        const unsigned char *cid, uint8_t cidl,
        bytearray *out)
{
    /* RFC 5246 (TLS 1.2) 6.2.3.3 defines the TLSCipherText.fragment as:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * In TLS 1.3 this explicit nonce is gone.
     * With AES GCM/CCM, "[content]" is actually the concatenation of the
     * ciphertext and authentication tag.
     */
    const uint16_t  version = TLSV1DOT2_VERSION;
    const bool      is_v12 = version == TLSV1DOT2_VERSION || version == DTLSV1DOT2_VERSION || version == TLCPV1_VERSION;
    gcry_error_t    err;
    const unsigned char   *explicit_nonce = NULL, *ciphertext;
    unsigned        ciphertext_len, auth_tag_len;
    unsigned char   nonce[12];
    const ssl_cipher_mode_t cipher_mode = mode;
    const bool      is_cid = ct == SSL_ID_TLS12_CID && version == DTLSV1DOT2_VERSION;
    // FIXME: PLACEHOLDER
    const uint8_t draft_version = 0;
    //const uint8_t   draft_version = ssl->session.tls13_draft_version;
    const unsigned char   *auth_tag_wire;
    unsigned char   auth_tag_calc[16];
    unsigned char  *aad = NULL;
    unsigned        aad_len = 0;
    
    // FIXME: PLACEHOLDER/DUMMY decoder
    SslDecoder *decoder = &(SslDecoder){.seq = 1, .epoch = 0, .evp = *cipher};

    switch (cipher_mode) {
    case MODE_GCM:
    case MODE_CCM:
    case MODE_POLY1305:
        auth_tag_len = 16;
        break;
    case MODE_CCM_8:
        auth_tag_len = 8;
        break;
    default:
        tls_bf_logf(ERROR, "in %s: Unsupported cipher!", __func__);
        return false;
    }

    /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        if (inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
            tls_bf_logf(
                ERROR,
                "in %s: Input %d is too small for explicit nonce %d and auth tag %d",
                __func__,
                inl,
                EXPLICIT_NONCE_LEN,
                auth_tag_len
            );
            return false;
        }
        explicit_nonce = in;
        ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
        ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
    } else if (version == TLSV1DOT3_VERSION || version == DTLSV1DOT3_VERSION || cipher_mode == MODE_POLY1305) {
        if (inl < auth_tag_len) {
            tls_bf_logf(ERROR, "in %s: Input %d has no space for auth tag %d", __func__, inl, auth_tag_len);
            return false;
        }
        ciphertext = in;
        ciphertext_len = inl - auth_tag_len;
    } else {
        tls_bf_logf(ERROR, "in %s: Unexpected TLS version %#x", __func__, version);
        return false;
    }
    auth_tag_wire = ciphertext + ciphertext_len;

    /*
     * Nonce construction is version-specific. Note that AEAD_CHACHA20_POLY1305
     * (RFC 7905) uses a nonce construction similar to TLS 1.3.
     */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        DISSECTOR_ASSERT(iv.len == IMPLICIT_NONCE_LEN);
        /* Implicit (4) and explicit (8) part of nonce. */
        memcpy(nonce, iv.data, IMPLICIT_NONCE_LEN);
        memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

    } else if (version == TLSV1DOT3_VERSION || version == DTLSV1DOT3_VERSION ||  cipher_mode == MODE_POLY1305) {
        /*
         * Technically the nonce length must be at least 8 bytes, but for
         * AES-GCM, AES-CCM and Poly1305-ChaCha20 the nonce length is exact 12.
         */
        const unsigned nonce_len = 12;
        DISSECTOR_ASSERT(iv.len == nonce_len);
        memcpy(nonce, iv.data, iv.len);
        /* Sequence number is left-padded with zeroes and XORed with write_iv */
        phton64(nonce + nonce_len - 8, pntoh64(nonce + nonce_len - 8) ^ decoder->seq);
    }

    /* Set nonce and additional authentication data */
    err = gcry_cipher_reset(*cipher);
    if (err != 0) {
        tls_bf_logf(ERROR, "in %s: %s: %s", __func__, gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    tls_bf_log_ssl_data(BF_DEBUG, "nonce", nonce, 12);
    err = gcry_cipher_setiv(decoder->evp, nonce, 12);
    if (err != 0) {
        tls_bf_logf(ERROR, "in %s: Failed to set nonce: %s", __func__, gcry_strerror(err));
        return false;
    }

    /* (D)TLS 1.2 needs specific AAD, TLS 1.3 (before -25) uses empty AAD. */
    if (is_cid) { /* if connection ID */
        // TODO: restore functionnality ? Though that is related to DTLS 1.2, which we might not care about really much
        //if (ssl->session.deprecated_cid) {
        if (false) {
            aad_len = 14 + cidl;
            aad = malloc(aad_len);
            phton64(aad, decoder->seq);         /* record sequence number */
            phton16(aad, decoder->epoch);       /* DTLS 1.2 includes epoch. */
            aad[8] = ct;                        /* TLSCompressed.type */
            phton16(aad + 9, record_version);   /* TLSCompressed.version */
            memcpy(aad + 11, cid, cidl);        /* cid */
            aad[11 + cidl] = cidl;              /* cid_length */
            phton16(aad + 12 + cidl, ciphertext_len);  /* TLSCompressed.length */
        } else {
            aad_len = 23 + cidl;
            aad = malloc(aad_len);
            memset(aad, 0xFF, 8);               /* seq_num_placeholder */
            aad[8] = ct;                        /* TLSCompressed.type */
            aad[9] = cidl;                      /* cid_length */
            aad[10] = ct;                       /* TLSCompressed.type */
            phton16(aad + 11, record_version);  /* TLSCompressed.version */
            phton64(aad + 13, decoder->seq);    /* record sequence number */
            phton16(aad + 13, decoder->epoch);  /* DTLS 1.2 includes epoch. */
            memcpy(aad + 21, cid, cidl);        /* cid */
            phton16(aad + 21 + cidl, ciphertext_len);  /* TLSCompressed.length */
        }
    } else if (is_v12) {
        aad_len = 13;
        aad = malloc(aad_len);
        phton64(aad, decoder->seq);         /* record sequence number */
        if (version == DTLSV1DOT2_VERSION) {
            phton16(aad, decoder->epoch);   /* DTLS 1.2 includes epoch. */
        }
        aad[8] = ct;                        /* TLSCompressed.type */
        phton16(aad + 9, record_version);   /* TLSCompressed.version */
        phton16(aad + 11, ciphertext_len);  /* TLSCompressed.length */
        tls_bf_log_ssl_data(BF_DEBUG, "aad", aad, aad_len);
    } else if (version == DTLSV1DOT3_VERSION) {
        // TODO: implement (though it seems that x-ray-tls-itself doesn't support DTLS in the first place)
        puts("Aborting: not yet implemented (lookup exit code in source)");
        exit(102);
        //aad_len = decoder->dtls13_aad.data_len;
        //aad = decoder->dtls13_aad.data;
    } else if (draft_version >= 25 || draft_version == 0) {
        aad_len = 5;
        aad = malloc(aad_len);
        aad[0] = ct;                        /* TLSCiphertext.opaque_type (23) */
        phton16(aad + 1, record_version);   /* TLSCiphertext.legacy_record_version (0x0303) */
        phton16(aad + 3, inl);              /* TLSCiphertext.length */
    }

    if (mode == MODE_CCM || mode == MODE_CCM_8) {
        /* size of plaintext, additional authenticated data and auth tag. */
        uint64_t lengths[3] = { ciphertext_len, aad_len, auth_tag_len };

        gcry_cipher_ctl(decoder->evp, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
        if (err != 0) {
            tls_bf_logf(ERROR, "in %s: %s: %s", __func__, gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
    }

    if (aad && aad_len > 0) {
        tls_bf_log_ssl_data(BF_DEBUG, "AAD", aad, aad_len);
        err = gcry_cipher_authenticate(decoder->evp, aad, aad_len);
        if (err) {
            tls_bf_logf(ERROR, "in %s: Failed to set AAD: %s", __func__, gcry_strerror(err));
            return false;
        }
    }

    /* Decrypt now that nonce and AAD are set. */
    err = gcry_cipher_decrypt(decoder->evp, out->data, out->len, ciphertext, ciphertext_len);
    if (err) {
        tls_bf_logf(ERROR, "in %s: Decrypt failed: %s", __func__, gcry_strerror(err));
        return false;
    }

    /* Check authentication tag for authenticity (replaces MAC) */
    err = gcry_cipher_gettag(decoder->evp, auth_tag_calc, auth_tag_len);
    if (err == 0 && !memcmp(auth_tag_calc, auth_tag_wire, auth_tag_len)) {
        tls_bf_log_ssl_data(INFO, "auth_tag(OK)", auth_tag_calc, auth_tag_len);
    } else {
        if (err) {
            tls_bf_logf(BF_DEBUG, "in %s: Cannot obtain tag: %s", __func__, gcry_strerror(err));
        } else {
            tls_bf_logf(BF_DEBUG, "in %s: Auth tag mismatch", __func__);
            tls_bf_log_ssl_data(BF_DEBUG, "\tauth_tag(calculated)", auth_tag_calc, auth_tag_len);
            tls_bf_log_ssl_data(BF_DEBUG, "\tauth_tag(packet)    ", (uint8_t *)auth_tag_wire, auth_tag_len);
        }
        return false;
    }

    tls_bf_log_ssl_data(INFO, "Plaintext", out->data, ciphertext_len);
    out->len = ciphertext_len;
    return true;
}

