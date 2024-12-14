#include <string.h>

#include "compass_dns.h"

DnsHeader parse_dns_header(const char *message_bytes) {
    DnsHeader dns_header;
    memcpy(&dns_header.id, message_bytes, 2);
    dns_header.qr = (message_bytes[2] & QR_BYTE_MASK) >> 7;
    dns_header.opcode = (message_bytes[2] & OPCODE_BYTE_MASK) >> 3;
    dns_header.aa = (message_bytes[2] & AA_BYTE_MASK) >> 2;
    dns_header.tc = (message_bytes[2] & TC_BYTE_MASK) >> 1;
    dns_header.rd = message_bytes[2] & RD_BYTE_MASK;
    dns_header.ra = (message_bytes[3] & RA_BYTE_MASK) >> 7;
    dns_header.z = (message_bytes[3] & Z_BYTE_MASK) >> 4;
    dns_header.rcode = message_bytes[3] & RCODE_BYTE_MASK;
    memcpy(&dns_header.qd_count, message_bytes + 4, 2);
    memcpy(&dns_header.an_count, message_bytes + 6, 2);
    memcpy(&dns_header.ns_count, message_bytes + 8, 2);
    memcpy(&dns_header.ar_count, message_bytes + 10, 2);
    return dns_header;
}
