#ifndef HEADER_CAPS_MADLIB
#define HEADER_CAPS_MADLIB

#include <stdlib.h>

typedef struct packet_t{
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *payload;
    int payload_length;
    char* packet;
}packet_t;

packet_t build_standard_packet(
    u_int16_t source_port,
    u_int16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address,
    u_int32_t packet_length,
    char* payload
    );

int packet_destroy(packet_t packet);

int set_TCP_flags(packet_t packet, int hex_flags);

int rawsocket_send(packet_t packet);

packet_t rawsocket_sniff();


#endif
