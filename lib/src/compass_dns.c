#include <string.h>
#include <arpa/inet.h>

#include "compass_dns.h"

#define STRING_END '\0'

void parse_dns_header(const u_int8_t *buffer, DnsHeader *dns_header) {
    memcpy(&dns_header->id, buffer, 2);
    dns_header->id = ntohs(dns_header->id);
    dns_header->qr = (buffer[2] & QR_BYTE_MASK) >> 7;
    dns_header->opcode = (buffer[2] & OPCODE_BYTE_MASK) >> 3;
    dns_header->aa = (buffer[2] & AA_BYTE_MASK) >> 2;
    dns_header->tc = (buffer[2] & TC_BYTE_MASK) >> 1;
    dns_header->rd = buffer[2] & RD_BYTE_MASK;
    dns_header->ra = (buffer[3] & RA_BYTE_MASK) >> 7;
    dns_header->z = (buffer[3] & Z_BYTE_MASK) >> 4;
    dns_header->rcode = buffer[3] & RCODE_BYTE_MASK;
    memcpy(&dns_header->qd_count, buffer + 4, 2);
    dns_header->qd_count = ntohs(dns_header->qd_count);
    memcpy(&dns_header->an_count, buffer + 6, 2);
    dns_header->an_count = ntohs(dns_header->an_count);
    memcpy(&dns_header->ns_count, buffer + 8, 2);
    dns_header->ns_count = ntohs(dns_header->ns_count);
    memcpy(&dns_header->ar_count, buffer + 10, 2);
    dns_header->ar_count = ntohs(dns_header->ar_count);
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

void parse_dns_questions(
    const u_int8_t *buffer_ptr,
    const u_int16_t qd_count,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
) {
    u_int16_t buffer_index = DNS_HEADER_SIZE;
    for (u_int16_t i = 0; i < qd_count; i++) {
        dns_questions_ptr += i;
        u_int16_t domain_index = 0;
        u_int8_t segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
        while (segment_indicator > 0) {
            if (segment_indicator & QUESTION_PTR_BYTE_MASK) {
                const u_int16_t offset = (segment_indicator & QUESTION_PTR_OFFSET_BYTE_MASK)
                                         * 256
                                         * buffer_ptr[buffer_index];
                buffer_index = offset;
                segment_indicator = buffer_ptr[buffer_index];
                continue;
            }
            if (domain_index > 0) {
                dns_questions_ptr->domain[domain_index] = '.';
                domain_index++;
            }
            memcpy(&dns_questions_ptr->domain[domain_index], buffer_ptr + buffer_index, segment_indicator);
            domain_index += segment_indicator;
            buffer_index += segment_indicator;
            segment_indicator = buffer_ptr[buffer_index];
            buffer_index++;
        }
        dns_questions_ptr->domain[domain_index] = STRING_END;
        memcpy(&dns_questions_ptr->q_type, buffer_ptr + buffer_index, 2);
        dns_questions_ptr->q_type = ntohs(dns_questions_ptr->q_type);
        buffer_index += 2;
        memcpy(&dns_questions_ptr->q_class, buffer_ptr + buffer_index, 2);
        dns_questions_ptr->q_class = ntohs(dns_questions_ptr->q_class);
        buffer_index += 2;
    }
    *questions_buffer_end_index_ptr = buffer_index - 1;
}
