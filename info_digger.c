#include "info_digger.h"
#include "log.h"
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

// Takes the `path` to a .pcap file and returns a `digger *` to dig information from this capture.
// TODO: implement a free function (even if this leak is very minor).
digger *digger_from_file(char* path) {
    digger *new_dig = malloc(sizeof(digger));
    pcap_init(PCAP_CHAR_ENC_LOCAL, new_dig->errbuf);
    if (new_dig->errbuf[0] != 0) {
        tls_bf_logf(ERROR, "in %s: %s", __func__, new_dig->errbuf);
        return NULL;
    }

    pcap_t* handle = pcap_open_offline(path, new_dig->errbuf);
    if (new_dig->errbuf[0] != 0) {
        tls_bf_logf(ERROR, "in %s: %s", __func__, new_dig->errbuf);
        return NULL;
    }
    new_dig->capture = handle;

    new_dig->dug_data.first_app_data = (bytearray){.data=NULL, .len=0};
    new_dig->dug_data.first_app_actor = NONE;
    new_dig->dug_data.cipher_suite = 0;
    new_dig->dug_data.server_random = (bytearray){.data=NULL, .len=0};
    new_dig->dug_data.tls_ver = 0;
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
    tls_bf_log(DEBUG, "Found record:");
    tls_bf_logf(DEBUG, "Content type: 0x%u", record->content_type);
    tls_bf_logf(DEBUG, "Version: 0x%04x", ntohs(record->ver));
    tls_bf_logf(DEBUG, "Length: 0x%04x", ntohs(record->len));
}

static void tls_handshake_debug_print(tls_handshake_hdr* handshake) {
    tls_bf_logf(DEBUG, "\tMessage type: 0x%02x", handshake->msg_type);
    tls_bf_logf(DEBUG, "\tLength: 0x%06x", ntohl(handshake->len) >> 8);
    tls_bf_logf(DEBUG, "\tVersion: 0x%04x", ntohs(handshake->ver));
}

static bool dig_complete(digger *self) {
    return self->dug_data.first_app_data.data != NULL
        && self->dug_data.first_app_actor != NONE
        && self->dug_data.cipher_suite != 0
        && self->dug_data.server_random.data != NULL
        && self->dug_data.tls_ver != 0;
}

static bool analyze_tls_record(digger* self, bytearray record_bytearray, tls_actor actor) {
    tls_record_hdr *record = (tls_record_hdr *) record_bytearray.data;
    tls_record_debug_print(record);
    uint16_t h_record_len = ntohs(record->len);

    if (record->content_type == TLS_HANDSHAKE) {
        tls_handshake_hdr *handshake_hdr = (tls_handshake_hdr *)((uint8_t*)record + 5);
        tls_handshake_debug_print(handshake_hdr);
        if (handshake_hdr->msg_type == TLS_HS_SERVER_HELLO) {
          
            self->dug_data.tls_ver = ntohs(handshake_hdr->ver);
            
            // TODO: verify correctness for TLS 1.3
            self->dug_data.server_random.len = 0x20;
            self->dug_data.server_random.data = malloc(self->dug_data.server_random.len);
            memcpy(self->dug_data.server_random.data,
                    (uint8_t *)handshake_hdr + 6,
                    self->dug_data.server_random.len);
           
            self->dug_data.cipher_suite = ntohs(*(uint16_t *)((uint8_t *)handshake_hdr + 6 + 0x41));
        }
        // TODO: cycle through the actual handshake headers? (but is it ever necessary?) (beware of misaligned len)
    } else if (record->content_type == TLS_APPLICATION) {
        self->dug_data.first_app_actor = actor;
        self->dug_data.first_app_data.len = h_record_len;
        self->dug_data.first_app_data.data = malloc(h_record_len);
        memcpy(self->dug_data.first_app_data.data, (uint8_t *)record + 5, h_record_len);
        return dig_complete(self); // should be !
    }

    // In the function name, record is singular. However, due to TCP reassembly shenanigans,
    // we might actually get multiple records in record_bytearray.
    if (h_record_len + 5 < record_bytearray.len) {
        record_bytearray.len -= h_record_len + 5;
        record_bytearray.data += h_record_len + 5;
        analyze_tls_record(self, record_bytearray, actor);
    } else if (h_record_len + 5 > record_bytearray.len) {
        tls_bf_log(WARNING, "Found a (smh) incomplete record! (use debug logs for more detail)");
    }

    return dig_complete(self);
}

// Find TLS version, algo, server random & first packet with digger.
// TODO: maybe get this off of libwireshark (though epan initialisation looks like a huge hassle).
// TODO: find tcp epoch for hmac based ciphers as well as other infos (cid ?) for cipher completeness.
dig_ret dig_dig_deep_deep(digger *self, port_list tls_ports) {
    // variables for TCP app content reassembly
    bytearray last_app_data = (bytearray){.data = NULL, .len = 0};
    tls_actor last_actor = NONE;
    uint32_t cur_ack = UINT32_MAX;
    uint32_t last_ack = UINT32_MAX;

    while (true) {
        int code = dig_next_packet(self);
        switch (code) {
            case 1:
                break;
            case PCAP_ERROR:
                tls_bf_logf(ERROR, "in %s: %s", __func__, pcap_geterr(self->capture));
                return DIG_PCAP_ERR;
            case PCAP_ERROR_BREAK:
                tls_bf_log(INFO, "Ran out of packets to dig...");
                return DIG_OUT_OF_PACKETS;
            case PCAP_ERROR_NOT_ACTIVATED:
                tls_bf_logf(ERROR, "in %s: pcap handle missing activation", __func__);
                return DIG_PCAP_ERR;
            default:
                tls_bf_logf(ERROR, "in %s: unknown libpcap error (%d)", __func__, code);
                return DIG_PCAP_ERR;
        }

        if (self->cur_hdr->len != self->cur_hdr->caplen) {
            tls_bf_logf(ERROR, "in %s: Found incomplete packet!! (bad capture ?)", __func__);
            return DIG_INCOMPLETE_CAPTURE;
        }

        const uint8_t *packet_hdr = self->cur_packet + ETHER_HDR_LEN;
        const uint8_t *segment_hdr;
        uint8_t proto;

        // TODO: handle potential vlan and other possible (common) encapsulations
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
                tls_bf_log(INFO, "Found unsupported (non ipv4 or ipv6) packet");
                continue;
        }

        // TODO: handle dtls & quic, ideally through separate functions if that is possible
        if (proto != IPPROTO_TCP) {
            tls_bf_log(INFO, "Found unsupported (non tcp) segment");
            continue;
        }

        struct tcphdr* tcp_hdr = (struct tcphdr *)segment_hdr;
        uint32_t tcp_hdr_len = tcp_hdr->doff * 4;
        uint32_t tcp_len = self->cur_packet + self->cur_hdr->caplen - segment_hdr;
        if (tcp_hdr_len >= tcp_len
                || self->cur_hdr->caplen == 60) { // caplen = 60 is most likely empty tcp w/ eth padding
            continue;
        }

        // Find out if packet is from client or server, or if there even is a TLS payload
        tls_actor actor = has_tls_actor(tcp_hdr->th_sport, tcp_hdr->th_dport, tls_ports);
        if (actor == NONE) {
            continue;
        }

        // Application data reassembly
        size_t data_len = self->cur_packet + self->cur_hdr->caplen - segment_hdr - tcp_hdr_len;
        cur_ack = tcp_hdr->ack_seq;

        if (cur_ack != last_ack) {
            // time to analyze reassembled data...
            if (last_app_data.data != NULL) {
                if (analyze_tls_record(self, last_app_data, last_actor)) {
                    return DIG_SUCCESS;
                };
            }

            // ...and pave the way for new data
            void *ret = realloc(last_app_data.data, data_len);
            
            if (ret == NULL) {
                tls_bf_log(ERROR, "No more memory left for realloc call, horrible things might be happening");
                return DIG_REALLOC_FAILURE;
            }
            last_app_data.data = ret;

            memcpy(last_app_data.data, segment_hdr + tcp_hdr_len, data_len);
            last_app_data.len = data_len;
            last_actor = actor;
        } else {
            void *ret = realloc(last_app_data.data, data_len + last_app_data.len);

            if (ret == NULL) {
                tls_bf_log(ERROR, "No more memory left for realloc call, horrible things might be happening");
                return DIG_REALLOC_FAILURE;
            }
            last_app_data.data = ret;

            memcpy(last_app_data.data + last_app_data.len, segment_hdr + tcp_hdr_len, data_len);
            last_app_data.len += data_len;
        }

        last_ack = cur_ack;
    }
    return DIG_SUCCESS;
}
