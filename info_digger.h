#ifndef INFO_DIGGER_H
#define INFO_DIGGER_H

#include "utils.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdint.h>

typedef enum {
    NONE,
    TLS_CLIENT,
    TLS_SERVER,
} tls_actor;

typedef struct _dug_data {
    uint16_t tls_ver;
    uint16_t cipher_suite;
    bytearray server_random;
    bytearray first_app_data;
    tls_actor first_app_actor;
} dug_data;

typedef struct _digger {
    pcap_t *capture;
    struct pcap_pkthdr *cur_hdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t *cur_packet;
    bytearray cur_packet_barr;
    dug_data dug_data;
} digger;

typedef enum _dig_ret {
    DIG_SUCCESS,
    DIG_OUT_OF_PACKETS,
    DIG_PCAP_ERR,
    DIG_INCOMPLETE_CAPTURE,
    DIG_REALLOC_FAILURE,
} dig_ret;

digger* digger_from_file(char* path);
dig_ret dig_dig_deep_deep(digger *self, port_list tls_ports);

// TODO: check correctness for 1.2 and 1.3 (current source is wikipedia)
typedef enum {
    TLS_CHANGE_CYPHER_SPEC = 20,
    TLS_ALERT = 21,
    TLS_HANDSHAKE = 22,
    TLS_APPLICATION = 23,
    TLS_HEARTBEAT = 24,
} tls_rec_content_type;

typedef struct _tls_record_hdr { // TODO: Big endian version, will have to test with qemu.
    uint8_t content_type:8;
    uint32_t ver:16;
    uint64_t len:16;
} tls_record_hdr;

// TODO: check correctness for 1.2 and 1.3 (current source is wikipedia)
typedef enum {
    TLS_HS_HELLO_REQUEST = 0,
    TLS_HS_CLIENT_HELLO = 1,
    TLS_HS_SERVER_HELLO = 2,
    TLS_HS_NEW_SESSION_TICKET = 4,
    TLS_HS_ENCRYPTED_EXTENSIONS = 8, // TLS 1.3 only
    TLS_HS_CERTIFICATE = 11,
    TLS_HS_SERVER_KEY_EXCHANGE = 12,
    TLS_HS_CERTIFICATE_REQUEST = 13,
    TLS_HS_SERVER_HELLO_DONE = 14,
    TLS_HS_CERTIFICATE_VERIFY = 15,
    TLS_HS_CLIENT_KEY_EXCHANGE = 16,
    TLS_HS_FINISHED = 20,
} tls_handshake_msg_type;

typedef struct _tls_handshake_hdr { // TODO: Big endian version, will have to test with qemu.
    uint8_t msg_type:8;
    uint32_t len:24;
    uint32_t ver:16;
} tls_handshake_hdr;

#endif
