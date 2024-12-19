#ifndef COMPASS_DNS_H
#define COMPASS_DNS_H

#include <stdlib.h>

#define DNS_HEADER_SIZE 12

const static u_int8_t QR_BYTE_MASK = 0b10000000;
const static u_int8_t OPCODE_BYTE_MASK = 0b01111000;
const static u_int8_t AA_BYTE_MASK = 0b00000100;
const static u_int8_t TC_BYTE_MASK = 0b00000010;
const static u_int8_t RD_BYTE_MASK = 0b00000001;
const static u_int8_t RA_BYTE_MASK = 0b10000000;
const static u_int8_t Z_BYTE_MASK = 0b01110000;
const static u_int8_t RCODE_BYTE_MASK = 0b00001111;

const static u_int8_t QUESTION_PTR_BYTE_MASK = 0b11000000;
const static u_int8_t QUESTION_PTR_OFFSET_BYTE_MASK = 0b00111111;

typedef enum OperationCode {
    OC_QUERY = 0,
    OC_IQUERY = 1,
    OC_STATUS = 2
} OperationCode;

typedef enum ResponseCode {
    RC_NO_ERROR = 0,
    RC_FORMAT_ERROR = 1,
    RC_SERVER_FAILURE = 2,
    RC_NAME_ERROR = 3,
    RC_NOT_IMPLEMENTED = 4,
    RC_REFUSED = 5
} ResponseCode;

typedef enum BaseType {
    TYPE_A = 1,
    TYPE_NS = 2,
    TYPE_MD = 3,
    TYPE_MF = 4,
    TYPE_CNAME = 5,
    TYPE_SOA = 6,
    TYPE_MB = 7,
    TYPE_MG = 8,
    TYPE_MR = 9,
    TYPE_NONE = 10,
    TYPE_WKS = 11,
    TYPE_PTR = 12,
    TYPE_HINFO = 13,
    TYPE_MINFO = 14,
    TYPE_MX = 15,
    TYPE_TXT = 16
} BaseType;

typedef enum QType {
    TYPE_AXFR = 252,
    TYPE_MAILB = 253,
    TYPE_MAILA = 254,
    TYPE_ALL = 255
} QType;

typedef enum BaseClass {
    CLASS_IN = 1,
    CLASS_CS = 2,
    CLASS_CH = 3,
    CLASS_HS = 4
} BaseClass;

typedef enum QClass {
    CLASS_ANY = 255
} QClass;


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

void parse_dns_header(const u_int8_t *buffer_ptr, DnsHeader *dns_header_ptr);

void dns_header_to_buffer(const DnsHeader *dns_header_ptr, u_int8_t *buffer_ptr);

typedef struct DnsQuestion {
    char domain[254];
    u_int16_t q_type;
    u_int16_t q_class;
} DnsQuestion;

void parse_dns_questions(
    const u_int8_t *buffer_ptr,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
);

#endif //COMPASS_DNS_H
