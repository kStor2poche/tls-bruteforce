#ifndef TLS_DECRYPT_H
#define TLS_DECRYPT_H

#include <gcrypt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* define from epan/proto.h */

#define REPORT_DISSECTOR_BUG(...)  \
    printf(__VA_ARGS__) // our "stub"

#define __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

#define __DISSECTOR_ASSERT(expression, file, lineno)  \
  (REPORT_DISSECTOR_BUG("%s:%u: failed assertion \"%s\"", \
        file, lineno, __DISSECTOR_ASSERT_STRINGIFY(expression)))

#define __DISSECTOR_ASSERT_STRINGIFY(s) # s

#define DISSECTOR_ASSERT(expression)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT (expression, __FILE__, __LINE__))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

/* all the following defines come from from packet-tls-utils.h, wireshark */
#define SSL_WRITE_KEY           1

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLCPV1_VERSION         0x101
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd
#define DTLSV1DOT3_VERSION     0xfefc

typedef enum {
    SSL_ID_CHG_CIPHER_SPEC         = 0x14,
    SSL_ID_ALERT                   = 0x15,
    SSL_ID_HANDSHAKE               = 0x16,
    SSL_ID_APP_DATA                = 0x17,
    SSL_ID_HEARTBEAT               = 0x18,
    SSL_ID_TLS12_CID               = 0x19,
    SSL_ID_DTLS13_ACK              = 0x1A,
} ContentType;

/* Explicit and implicit nonce length (RFC 5116 - Section 3.2.1) */
#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8
#define TLS13_AEAD_NONCE_LENGTH     12

/* from wsutils/pint.h */
static inline void phton64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
}
static inline uint64_t pntoh64(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<56|
           (uint64_t)*((const uint8_t *)(p)+1)<<48|
           (uint64_t)*((const uint8_t *)(p)+2)<<40|
           (uint64_t)*((const uint8_t *)(p)+3)<<32|
           (uint64_t)*((const uint8_t *)(p)+4)<<24|
           (uint64_t)*((const uint8_t *)(p)+5)<<16|
           (uint64_t)*((const uint8_t *)(p)+6)<<8|
           (uint64_t)*((const uint8_t *)(p)+7)<<0;
}
static inline void phton16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}

/* helper stub */
void inline ssl_print_data(const char *header, uint8_t *bytes, size_t byte_len) {
    printf("%s: 0x", header);
    for (size_t i = 0; i < byte_len; i++) {
        printf("%02x", bytes[i]);
    }
    puts("");
}

#define G_STRFUNC __func__

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

#endif
