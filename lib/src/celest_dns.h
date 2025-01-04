#ifndef COMPASS_DNS_H
#define COMPASS_DNS_H

#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define MAX_DOMAIN_SIZE 253
#define MAX_DNS_MESSAGE_SIZE 512

const static uint8_t QR_BYTE_MASK = 0b10000000;
const static uint8_t OPCODE_BYTE_MASK = 0b01111000;
const static uint8_t AA_BYTE_MASK = 0b00000100;
const static uint8_t TC_BYTE_MASK = 0b00000010;
const static uint8_t RD_BYTE_MASK = 0b00000001;
const static uint8_t RA_BYTE_MASK = 0b10000000;
const static uint8_t Z_BYTE_MASK = 0b01110000;
const static uint8_t RCODE_BYTE_MASK = 0b00001111;

const static uint8_t QUESTION_PTR_BYTE_MASK = 0b11000000;
const static uint8_t QUESTION_PTR_OFFSET_BYTE_MASK = 0b00111111;

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
    TYPE_TXT = 16,
    TYPE_AAAA = 28
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

typedef struct DnsHeader {
    uint16_t id;
    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t z;
    uint8_t rcode;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} DnsHeader;

typedef struct DnsQuestion {
    char *domain;
    uint16_t q_type;
    uint16_t q_class;
} DnsQuestion;

typedef struct DnsRecord {
    char *domain;
    uint16_t r_type;
    uint16_t r_class;
    uint32_t ttl;
    uint16_t rd_length;
    uint8_t *r_data;
} DnsRecord;

typedef struct DnsMessage {
    DnsHeader header;
    DnsQuestion *questions;
    DnsRecord *answers;
    DnsRecord *authorities;
    DnsRecord *additional;
} DnsMessage;

void parse_dns_header(const uint8_t *buffer_ptr, DnsHeader *dns_header_ptr);

int parse_dns_message(const uint8_t *buffer_ptr, DnsMessage *dns_message_ptr);

uint8_t *dns_message_to_buffer(const DnsMessage *dns_message, uint16_t *buffer_size_ptr);

void free_dns_message(DnsMessage *dns_message);

#endif //COMPASS_DNS_H
