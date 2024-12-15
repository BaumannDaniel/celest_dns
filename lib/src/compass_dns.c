#include <string.h>
#include <arpa/inet.h>

#include "compass_dns.h"

DnsHeader parse_dns_header(const char *message_bytes) {
    DnsHeader dns_header;
    memcpy(&dns_header.id, message_bytes, 2);
    dns_header.id = ntohs(dns_header.id);
    dns_header.qr = (message_bytes[2] & QR_BYTE_MASK) >> 7;
    dns_header.opcode = (message_bytes[2] & OPCODE_BYTE_MASK) >> 3;
    dns_header.aa = (message_bytes[2] & AA_BYTE_MASK) >> 2;
    dns_header.tc = (message_bytes[2] & TC_BYTE_MASK) >> 1;
    dns_header.rd = message_bytes[2] & RD_BYTE_MASK;
    dns_header.ra = (message_bytes[3] & RA_BYTE_MASK) >> 7;
    dns_header.z = (message_bytes[3] & Z_BYTE_MASK) >> 4;
    dns_header.rcode = message_bytes[3] & RCODE_BYTE_MASK;
    memcpy(&dns_header.qd_count, message_bytes + 4, 2);
    dns_header.qd_count = ntohs(dns_header.qd_count);
    memcpy(&dns_header.an_count, message_bytes + 6, 2);
    dns_header.an_count = ntohs(dns_header.an_count);
    memcpy(&dns_header.ns_count, message_bytes + 8, 2);
    dns_header.ns_count = ntohs(dns_header.ns_count);
    memcpy(&dns_header.ar_count, message_bytes + 10, 2);
    dns_header.ar_count = ntohs(dns_header.ar_count);
    return dns_header;
}

void dns_header_to_buffer(const DnsHeader *dns_header, u_int8_t *buffer) {
    const u_int16_t id = htons(dns_header->id);
    memcpy(buffer, &id, 2);
    buffer[2] = 0;
    if (dns_header->qr) buffer[2] += QR_BYTE_MASK;
    buffer[2] += dns_header->opcode << 3;
    if (dns_header->aa) buffer[2] += AA_BYTE_MASK;
    if (dns_header->tc) buffer[2] += TC_BYTE_MASK;
    if (dns_header->rd) buffer[2] += RD_BYTE_MASK;
    buffer[3] = 0;
    if (dns_header->ra) buffer[3] += RA_BYTE_MASK;
    buffer[3] += dns_header->z << 4;
    buffer[3] += dns_header->rcode;
    const u_int16_t qd_count = htons(dns_header->qd_count);
    memcpy(buffer + 4, &qd_count, 2);
    const u_int16_t an_count = htons(dns_header->an_count);
    memcpy(buffer + 6, &an_count, 2);
    const u_int16_t ns_count = htons(dns_header->ns_count);
    memcpy(buffer + 8, &ns_count, 2);
    const u_int16_t ar_count = htons(dns_header->ar_count);
    memcpy(buffer + 10, &ar_count, 2);
}
