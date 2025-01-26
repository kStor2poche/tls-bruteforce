#include "info_digger.h"
#include "utils.h"
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <string.h>

digger *digger_from_file(char* path) {
    digger *new_dig = malloc(sizeof(digger));
    pcap_init(PCAP_CHAR_ENC_LOCAL, new_dig->errbuf);
    if (new_dig->errbuf[0] != 0) {
        fprintf(stderr, "Error: in %s: %s\n", __func__, new_dig->errbuf);
        return NULL;
    }

    pcap_t* handle = pcap_open_offline(path, new_dig->errbuf);
    if (new_dig->errbuf[0] != 0) {
        fprintf(stderr, "Error: in %s: %s\n", __func__, new_dig->errbuf);
        return NULL;
    }
    new_dig->capture = handle;
    return new_dig;
}

static int dig_next_packet(digger *self) {
    int res = pcap_next_ex(self->capture, &self->cur_hdr, &self->cur_packet);
    if (res == 1) {
        self->cur_packet_barr.data = (uint8_t*)self->cur_packet;
        self->cur_packet_barr.len = self->cur_hdr->caplen;
    }
    return res;
}

// TODO: maybe replace because it might not be _that_ useful
static inline int ether_type(digger *self) {
    struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header*) self->cur_packet;
    
    return ntohs(eth_hdr->ether_type);
}

typedef enum {
    NONE,
    TLS_CLIENT,
    TLS_SERVER,
} tls_actor;

static tls_actor has_tls_actor(short sport, short dport, port_list tls_ports) {
    uint16_t nsport = htons(sport);
    uint16_t ndport = htons(dport);

    for (int i=0; i<tls_ports.len; i++) {
        if (nsport == tls_ports.ports[i]) {
            return TLS_SERVER;
        }
        if (ndport == tls_ports.ports[i]) {
            return TLS_CLIENT;
        }
    }
    return NONE;
}

static void tls_record_debug_print(tls_record_hdr* record) {
    printf("Content type: 0x%u\n", record->content_type);
    printf("Version: 0x%04x\n", ntohs(record->ver));
    printf("Length: 0x%04x\n", ntohs(record->len));
}

static void tls_handshake_debug_print(tls_handshake_hdr* handshake) {
    printf("\tMessage type: 0x%02x\n", handshake->msg_type);
    printf("\tLength: 0x%06x\n", ntohl(handshake->len));
    printf("\tVersion: 0x%04x\n", ntohs(handshake->ver));
}

// TODO: change return type accordingly etc etc ? Or use digger ?
static void analyze_tls_record(digger* self, tls_record_hdr *record, tls_actor actor) {
    // In function name, record is singular, but due to TCP reassembly shenanigans,
    // we might get multiple records in one go
    puts("");
    tls_record_debug_print(record);
    record->len;
    if (record->content_type == TLS_HANDSHAKE) {
        tls_handshake_hdr *handshake_hdr = (tls_handshake_hdr *)((uint8_t*)record + 5);
        tls_handshake_debug_print(handshake_hdr);
        if (handshake_hdr->msg_type == TLS_HS_SERVER_HELLO) {
        }
    }
}

// Finds TLS version, algo, server random & first packet from capture (with tcp epoch for hmac ?)
dig_ret dig_dig_deep_deep(digger *self, port_list tls_ports) {
    // variables for TCP app content reassembly
    bytearray last_app_data = (bytearray){.data = NULL, .len = 0};
    uint32_t cur_ack = UINT32_MAX;
    uint32_t last_ack = UINT32_MAX;
    bool last_reassembled = false;

    while (true) {
        int code = dig_next_packet(self);
        // TODO: switch case-ify ?
        switch (code) {
            case 1:
                break;
            case PCAP_ERROR:
                fprintf(stderr, "Error: in %s: %s\n", __func__, pcap_geterr(self->capture));
                break;
            case PCAP_ERROR_BREAK:
                // TODO: maybe return a CAPTURE_INCOMPLETE-ish return val ?
                puts("Info: ran out of packets to dig...");
                return 1;
                break;
            case PCAP_ERROR_NOT_ACTIVATED:
                fprintf(stderr, "Error: in %s: pcap handle missing activation\n", __func__);
                break;
            default:
                fprintf(stderr, "Error: in %s: unknown libpcap error (%d)\n", __func__, code);
                break;
        }
        if (code != 1) {
            return DIG_PCAP_ERR;
        }

        if (self->cur_hdr->len != self->cur_hdr->caplen) {
            fputs("Error: Found incomplete packet!! (bad capture ?)", stderr);
            return DIG_INCOMPLETE_CAPTURE;
        }

        // TODO: handle potential vlan and more
        const uint8_t *packet_hdr = self->cur_packet + ETHER_HDR_LEN;
        const uint8_t *segment_hdr;
        uint8_t proto;

        // skip if packet isn't ip or ipv6
        switch (ether_type(self)) {
            case ETHERTYPE_IP: // TODO: test & implement some ipv4 defrag ?
                struct iphdr *ip_hdr = (struct iphdr *)packet_hdr;
                segment_hdr = (const uint8_t *) ip_hdr + ip_hdr->ihl * 4;
                proto = *(packet_hdr + 9);
                break;
            case ETHERTYPE_IPV6:
                struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)packet_hdr;
                proto = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
                segment_hdr = packet_hdr + 0x28; // ipv6 has a fixed length header
                break;
            default:
                continue;
        }

        // TODO: handle dtls & quic
        if (proto != IPPROTO_TCP) {
            continue;
        }

        struct tcphdr* tcp_hdr = (struct tcphdr *)segment_hdr;
        uint8_t tcp_hdr_len = tcp_hdr->doff * 4;
        if (tcp_hdr_len >= (self->cur_packet + self->cur_hdr->caplen - segment_hdr)) {
            continue;
        }

        tls_actor actor = has_tls_actor(tcp_hdr->th_sport, tcp_hdr->th_dport, tls_ports);
        if (actor == NONE) {
            continue;
        }

        // TCP "fragmentation" handling
        size_t data_len = self->cur_packet + self->cur_hdr->caplen - segment_hdr - tcp_hdr_len;
        cur_ack = tcp_hdr->ack_seq;

        if (cur_ack != last_ack) {
            // time to analyze reassembled packet
            if (last_app_data.data != NULL) {
                tls_record_hdr *record = (tls_record_hdr *) last_app_data.data;
                analyze_tls_record(self, record, actor);
            }

            void *ret = realloc(last_app_data.data, data_len);
            
            if (ret == NULL) {
                fputs("Error: no more memory left for realloc call, horrible things might be happening", stderr);
                return DIG_REALLOC_FAILURE;
            }
            last_app_data.data = ret;

            memcpy(last_app_data.data, segment_hdr + tcp_hdr_len, data_len);
            last_app_data.len = data_len;
            //print_bytearray(last_app_data);
        } else {
            void *ret = realloc(last_app_data.data, data_len + last_app_data.len);

            if (ret == NULL) {
                fputs("Error: no more memory left for realloc call, horrible things might be happening", stderr);
                return DIG_REALLOC_FAILURE;
            }
            last_app_data.data = ret;

            memcpy(last_app_data.data + last_app_data.len, segment_hdr + tcp_hdr_len, data_len);
            last_app_data.len += data_len;
            last_reassembled = true;
        }

        last_ack = cur_ack;
    }
    return DIG_SUCCESS;
}
