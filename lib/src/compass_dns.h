#ifndef COMPASS_DNS_H
#define COMPASS_DNS_H

#include <stdlib.h>

const static u_int8_t QR_BYTE_MASK = 0b10000000;
const static u_int8_t OPCODE_BYTE_MASK = 0b01111000;
const static u_int8_t AA_BYTE_MASK = 0b00000100;
const static u_int8_t TC_BYTE_MASK = 0b00000010;
const static u_int8_t RD_BYTE_MASK = 0b00000001;
const static u_int8_t RA_BYTE_MASK = 0b10000000;
const static u_int8_t Z_BYTE_MASK = 0b01110000;
const static u_int8_t RCODE_BYTE_MASK = 0b00001111;

enum OperationCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2
};

enum ResponseCode {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    REFUSED = 5
};

enum BaseType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NONE = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16
};

enum QType {
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255
};

enum BaseClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};

enum QClass {
    ANY = 255
};


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

void parse_dns_header(const u_int8_t *buffer, DnsHeader *dns_header);

void dns_header_to_buffer(const DnsHeader *dns_header, u_int8_t *buffer);

typedef struct DnsQuestion {
    char **domain_ptr;
    u_int16_t q_type;
    u_int16_t q_class;
} DnsQuestion;

void parse_dns_questions(
    u_int8_t *buffer_ptr,
    u_int16_t qd_count,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
);

#endif //COMPASS_DNS_H
