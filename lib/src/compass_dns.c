#include <string.h>

#include "compass_dns.h"

#define STRING_END '\0'

static u_int16_t big_endian_chars_to_short(const u_int8_t most_sig_char, const u_int8_t least_sig_char) {
    return most_sig_char * 256 + least_sig_char;
}

static void short_to_big_endian_chars(u_int8_t *big_endian_chars_ptr, const u_int16_t value) {
    big_endian_chars_ptr[1] = value % 256;
    big_endian_chars_ptr[0] = (value - big_endian_chars_ptr[1]) / 256;
}

static u_int16_t calc_domain_size(const u_int8_t *buffer_ptr, u_int16_t buffer_index) {
    u_int16_t domain_length = 0;
    u_int8_t segment_indicator = buffer_ptr[buffer_index];
    buffer_index++;
    while (segment_indicator > 0) {
        if (segment_indicator & QUESTION_PTR_BYTE_MASK) {
            const u_int16_t offset = big_endian_chars_to_short(
                segment_indicator & QUESTION_PTR_OFFSET_BYTE_MASK,
                buffer_ptr[buffer_index]
            );
            buffer_index = offset;
            segment_indicator = buffer_ptr[buffer_index];
            buffer_index++;
            continue;
        }
        // account for '.' separator
        if (domain_length > 0) domain_length++;
        domain_length += segment_indicator;
        buffer_index += segment_indicator;
        segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
    }
    // accounting for string end char
    return domain_length + 1;
}

static void retrieve_domain(
    const u_int8_t *buffer_ptr,
    u_int16_t buffer_index,
    char *domain_ptr,
    u_int16_t *domain_end_ptr
) {
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
            domain_ptr[domain_index] = '.';
            domain_index++;
        }
        memcpy(domain_ptr + domain_index, buffer_ptr + buffer_index, segment_indicator);
        domain_index += segment_indicator;
        buffer_index += segment_indicator;
        segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
    }
    domain_ptr[domain_index] = STRING_END;
    if (domain_pointer_end_index > 0) buffer_index = domain_pointer_end_index;
    *domain_end_ptr = buffer_index - 1;
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
    short_to_big_endian_chars(buffer_ptr, dns_header_ptr->id);
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
    short_to_big_endian_chars(buffer_ptr + 4, dns_header_ptr->qd_count);
    short_to_big_endian_chars(buffer_ptr + 6, dns_header_ptr->an_count);
    short_to_big_endian_chars(buffer_ptr + 8, dns_header_ptr->ns_count);
    short_to_big_endian_chars(buffer_ptr + 10, dns_header_ptr->ar_count);
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
        dns_questions_ptr->domain_size = calc_domain_size(buffer_ptr, buffer_index);
        dns_questions_ptr->domain = calloc(dns_questions_ptr->domain_size, sizeof(char));
        retrieve_domain(buffer_ptr, buffer_index, dns_questions_ptr->domain, &buffer_index);
        buffer_index++;
        dns_questions_ptr->q_type = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
        dns_questions_ptr->q_class = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
    }
    *questions_buffer_end_index_ptr = buffer_index - 1;
}

void free_dns_question(const DnsQuestion *dns_question) {
    free(dns_question->domain);
}

void free_dns_questions(const DnsQuestion *dns_questions, const u_int16_t qd_count) {
    for (int i = 0; i < qd_count; i++) {
        free_dns_question(dns_questions + i);
    }
}
