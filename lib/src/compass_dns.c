#include <string.h>
#include <arpa/inet.h>

#include "compass_dns.h"

#define STRING_END '\0'

static u_int16_t big_endian_chars_to_short(const uint8_t most_sig_char, const uint8_t least_sig_char) {
    return most_sig_char * 256 + least_sig_char;
}

void parse_dns_header(const u_int8_t *buffer_ptr, DnsHeader *dns_header_ptr) {
    dns_header_ptr->id = big_endian_chars_to_short(buffer_ptr[0], buffer_ptr[1]);
    dns_header_ptr->qr = (buffer_ptr[2] & QR_BYTE_MASK) >> 7;
    dns_header_ptr->opcode = (buffer_ptr[2] & OPCODE_BYTE_MASK) >> 3;
    dns_header_ptr->aa = (buffer_ptr[2] & AA_BYTE_MASK) >> 2;
    dns_header_ptr->tc = (buffer_ptr[2] & TC_BYTE_MASK) >> 1;
    dns_header_ptr->rd = buffer_ptr[2] & RD_BYTE_MASK;
    dns_header_ptr->ra = (buffer_ptr[3] & RA_BYTE_MASK) >> 7;
    dns_header_ptr->z = (buffer_ptr[3] & Z_BYTE_MASK) >> 4;
    dns_header_ptr->rcode = buffer_ptr[3] & RCODE_BYTE_MASK;
    dns_header_ptr->qd_count = big_endian_chars_to_short(buffer_ptr[4], buffer_ptr[5]);
    dns_header_ptr->an_count = big_endian_chars_to_short(buffer_ptr[6], buffer_ptr[7]);
    dns_header_ptr->ns_count = big_endian_chars_to_short(buffer_ptr[8], buffer_ptr[9]);
    dns_header_ptr->ar_count = big_endian_chars_to_short(buffer_ptr[10], buffer_ptr[11]);
}

void dns_header_to_buffer(const DnsHeader *dns_header_ptr, u_int8_t *buffer_ptr) {
    const u_int16_t id = htons(dns_header_ptr->id);
    memcpy(buffer_ptr, &id, 2);
    buffer_ptr[2] = 0;
    if (dns_header_ptr->qr) buffer_ptr[2] += QR_BYTE_MASK;
    buffer_ptr[2] += dns_header_ptr->opcode << 3;
    if (dns_header_ptr->aa) buffer_ptr[2] += AA_BYTE_MASK;
    if (dns_header_ptr->tc) buffer_ptr[2] += TC_BYTE_MASK;
    if (dns_header_ptr->rd) buffer_ptr[2] += RD_BYTE_MASK;
    buffer_ptr[3] = 0;
    if (dns_header_ptr->ra) buffer_ptr[3] += RA_BYTE_MASK;
    buffer_ptr[3] += dns_header_ptr->z << 4;
    buffer_ptr[3] += dns_header_ptr->rcode;
    const u_int16_t qd_count = htons(dns_header_ptr->qd_count);
    memcpy(buffer_ptr + 4, &qd_count, 2);
    const u_int16_t an_count = htons(dns_header_ptr->an_count);
    memcpy(buffer_ptr + 6, &an_count, 2);
    const u_int16_t ns_count = htons(dns_header_ptr->ns_count);
    memcpy(buffer_ptr + 8, &ns_count, 2);
    const u_int16_t ar_count = htons(dns_header_ptr->ar_count);
    memcpy(buffer_ptr + 10, &ar_count, 2);
}

void parse_dns_questions(
    const u_int8_t *buffer_ptr,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
) {
    const u_int16_t qd_count = big_endian_chars_to_short(buffer_ptr[4], buffer_ptr[5]);
    u_int16_t buffer_index = DNS_HEADER_SIZE;
    for (u_int16_t i = 0; i < qd_count; i++) {
        dns_questions_ptr += i;
        u_int16_t domain_index = 0;
        // caches buffer index when buffer index is set to domain pointer
        u_int16_t domain_pointer_end_index = 0;
        u_int8_t segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
        while (segment_indicator > 0) {
            if (segment_indicator & QUESTION_PTR_BYTE_MASK) {
                const u_int16_t offset = big_endian_chars_to_short(
                    segment_indicator & QUESTION_PTR_OFFSET_BYTE_MASK,
                    buffer_ptr[buffer_index]
                );
                domain_pointer_end_index = buffer_index + 1;
                buffer_index = offset;
                segment_indicator = buffer_ptr[buffer_index];
                buffer_index++;
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
        if (domain_pointer_end_index > 0) buffer_index = domain_pointer_end_index;
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
