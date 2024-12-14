#ifndef COMPASS_DNS_H
#define COMPASS_DNS_H

#include <stdlib.h>

/**
* Struct to represent a dns message headers
*
* id (u_int16): 2 byte message id
* qr (u_int8): 1 if message is response and 0 if query. First bit of third header byte.
* opcode (u_int8): operation code. 4 bits
* aa (u_int8): authoritative answer. True if server own queried domain.
* tc (u_int8): truncation, indicates if message was larger than 512 bytes
* rd (u_int8): recursion desired: if 1, then server should recursively resolve the query
* ra (u_int8): recursion available: set by server if recursion is available
* z (u_int8): reserved for dnssec queries. 3 bits
* rcode (u_int8): response code: status of response. 4 bits
* qd_count (u_int16) question count: number of questions in the messages question section. 2 bytes
* an_count (u_int16) answer record count: number records in the messages answer section. 2 bytes
* ns_count (u_int16) authority record count: number of records in the messages authority section. 2 bytes
* ar_count (u_int16) additional records count: number of records in the messages additional section. 2 bytes
*/
typedef struct DnsHeader {
    u_int16_t id;
    u_int8_t qr;
    u_int8_t opcode;
    u_int8_t aa;
    u_int8_t tc;
    u_int8_t rd;
    u_int8_t ra;
    u_int8_t z;
    u_int8_t rcode;
    u_int16_t qd_count;
    u_int16_t an_count;
    u_int16_t ns_count;
    u_int16_t ar_count;
} DnsHeader;

#endif //COMPASS_DNS_H
